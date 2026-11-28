<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attestation.php';

use Atlas\Pca\Attestation;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\TransparencyLedger;
use PHPUnit\Framework\TestCase;

/** The N-of-M multi-root verifier and the evidence anchoring. */
final class AttestSurvivorKill7AttestationMultiTest extends TestCase
{
    private static function good(array $m = []): \Closure
    {
        return static fn(): Obj => Obj::of(['ok' => true, 'bound' => true, 'measured' => Obj::of($m + ['model_id' => 'm'])]);
    }

    private static function answers(mixed $res): \Closure
    {
        return static fn(): mixed => $res;
    }

    private static function root(string $id, \Closure $v, bool $required = false): Obj
    {
        $o = Obj::of(['id' => $id, 'verifier' => $v]);
        if ($required) {
            $o->set('required', true);
        }
        return $o;
    }

    private static function verifyMulti(array $roots, int|float $thr = 1): array
    {
        return Attestation::createMultiRootVerifier(Obj::of(['threshold' => $thr, 'roots' => $roots]))(new Obj());
    }

    private static function thrown(\Closure $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . '|' . $e->getMessage();
        }
        return 'none';
    }

    // ---- construction ----------------------------------------------------------------------------------------------------------------

    /** A missing, non-list or empty root set is refused with the roots message. */
    public function testRootSetsAreValidated(): void
    {
        $want = 'TypeError|createMultiRootVerifier: at least one attestation root is required';
        $one = self::root('a', self::good());
        foreach ([Obj::of(['threshold' => 1]), Obj::of(['threshold' => 1, 'roots' => new Obj()]), Obj::of(['threshold' => 1, 'roots' => ['k' => $one]]),
            Obj::of(['threshold' => 1, 'roots' => []]), Obj::of(['threshold' => 1, 'roots' => null])] as $i => $p) {
            self::assertSame($want, self::thrown(static fn() => Attestation::createMultiRootVerifier($p)), (string)$i);
        }
    }

    /** The threshold must be an integer in [1, number of roots]. */
    public function testThresholdIsValidated(): void
    {
        $want = 'TypeError|createMultiRootVerifier: threshold must be an integer in [1, roots.length]';
        $roots = [self::root('a', self::good()), self::root('b', self::good())];
        foreach ([[], ['threshold' => null], ['threshold' => 1.5], ['threshold' => 0], ['threshold' => 3], ['threshold' => NAN], ['threshold' => INF], ['threshold' => '1']] as $i => $p) {
            $pol = Obj::of($p + ['roots' => $roots]);
            self::assertSame($want, self::thrown(static fn() => Attestation::createMultiRootVerifier($pol)), (string)$i);
        }
        foreach ([1, 2, 2.0] as $t) {
            self::assertSame('none', self::thrown(static fn() => Attestation::createMultiRootVerifier(Obj::of(['threshold' => $t, 'roots' => $roots]))), (string)$t);
        }
    }

    // ---- the required root and the malformed-result path ---------------------------------------------------------------------------------

    /** The FIRST failing required root is the one named; later roots are not consulted. */
    public function testTheFirstFailingRequiredRootIsNamed(): void
    {
        $r = self::verifyMulti([self::root('r1', self::answers(Obj::of(['ok' => false, 'reason' => 'nope1'])), true),
            self::root('r2', self::answers(Obj::of(['ok' => false, 'reason' => 'nope2'])), true)]);
        self::assertSame(['ok' => false, 'reason' => "required attestation root 'r1' failed: nope1"], $r);
    }

    /** A required root whose result is not an object (null, a PHP assoc array) is a malformed result, named by its own id. */
    public function testAMalformedRequiredResultIsNamed(): void
    {
        $want = ['ok' => false, 'reason' => "required attestation root 'r1' failed: root 'r1' returned a malformed result (fail closed)"];
        foreach ([null, ['ok' => true], 'x'] as $bad) {
            self::assertSame($want, self::verifyMulti([self::root('r0', self::good()), self::root('r1', self::answers($bad), true)]), json_encode($bad));
        }
    }

    /** A required root's failure text is its reason, or "invalid" when it gives none. */
    public function testARequiredRootReasonOrInvalid(): void
    {
        $why = static fn(mixed $res): array => self::verifyMulti([self::root('r0', self::answers($res), true)]);
        self::assertSame(['ok' => false, 'reason' => "required attestation root 'r0' failed: invalid"], $why(Obj::of(['ok' => false])));
        self::assertSame(['ok' => false, 'reason' => "required attestation root 'r0' failed: invalid"], $why(Obj::of(['ok' => false, 'reason' => null])));
        self::assertSame(['ok' => false, 'reason' => "required attestation root 'r0' failed: why"], $why(Obj::of(['ok' => false, 'reason' => 'why'])));
    }

    /** A required root that throws is refused with the exception text, or "unknown". */
    public function testARequiredRootThatThrows(): void
    {
        foreach (['boom' => 'boom', '' => 'unknown'] as $msg => $shown) {
            $r = self::verifyMulti([self::root('x', static function () use ($msg): never {
                throw new \RuntimeException((string)$msg);
            }, true)]);
            self::assertSame(['ok' => false, 'reason' => "required attestation root 'x' failed: root 'x' threw (fail closed): " . $shown], $r);
        }
    }

    /** A non-object answer, or an object that is not ok, never counts toward the threshold. */
    public function testOnlyOkBoundMeasuredResultsCount(): void
    {
        $below = ['ok' => false, 'reason' => 'multi-root attestation below threshold (0/1 independent roots corroborated)'];
        self::assertSame($below, self::verifyMulti([self::root('a', self::answers(null))]));
        self::assertSame($below, self::verifyMulti([self::root('a', self::answers(Obj::of(['ok' => false, 'bound' => true, 'measured' => Obj::of(['model_id' => 'm'])])))]));
    }

    // ---- the merged identity -----------------------------------------------------------------------------------------------------------

    /** Every measured field of a passing root appears in the merged identity, and weights are measured when a root measured the agreed digest. */
    public function testMergedIdentityAndMeasuredWeights(): void
    {
        $r = self::verifyMulti([self::root('a', self::good(['weights_digest' => 'w', 'weights_measured' => true, 'runtime_measurement' => 'rt', 'operator' => 'op',
            'system_prompt_digest' => 'sp', 'tool_manifest_digest' => 'tm']))]);
        self::assertSame(['ok', 'bound', 'measured'], array_keys($r));
        self::assertSame(['model_id', 'weights_digest', 'weights_measured', 'runtime_measurement', 'operator', 'system_prompt_digest', 'tool_manifest_digest'], $r['measured']->keys());
        self::assertTrue($r['measured']->get('weights_measured'));
        self::assertSame(['m', 'w', 'rt', 'op', 'sp', 'tm'], array_map(static fn(string $k) => $r['measured']->get($k),
            ['model_id', 'weights_digest', 'runtime_measurement', 'operator', 'system_prompt_digest', 'tool_manifest_digest']));
    }

    /** Self-asserted weights stay unmeasured, and absent digests are left out of the merged identity. */
    public function testUnmeasuredWeightsAndAbsentDigests(): void
    {
        foreach ([['weights_digest' => 'w', 'weights_measured' => false], ['weights_digest' => 'w']] as $m) {
            $r = self::verifyMulti([self::root('a', self::good($m))]);
            self::assertFalse($r['measured']->get('weights_measured'));
            self::assertSame(['model_id', 'weights_digest', 'weights_measured', 'runtime_measurement', 'operator'], $r['measured']->keys());
        }
    }

    /** A root measuring weights under a different (empty) digest does not make the agreed digest measured. */
    public function testMeasuredFlagNeedsTheAgreedDigest(): void
    {
        $r = self::verifyMulti([self::root('a', self::good(['weights_digest' => 'w', 'weights_measured' => false])),
            self::root('b', self::good(['weights_digest' => '', 'weights_measured' => true]))], 2);
        self::assertSame('w', $r['measured']->get('weights_digest'));
        self::assertFalse($r['measured']->get('weights_measured'));
    }

    /** A root that lacks a field does not stop the later roots from supplying it. */
    public function testALaterRootSuppliesAMissingField(): void
    {
        $r = self::verifyMulti([self::root('a', self::good()), self::root('b', self::good(['operator' => 'op2', 'weights_digest' => 'w2']))], 2);
        self::assertSame('op2', $r['measured']->get('operator'));
        self::assertSame('w2', $r['measured']->get('weights_digest'));
    }

    /** Two roots that disagree on a measured field deny, naming both roots. */
    public function testDisagreeingRootsConflict(): void
    {
        $r = self::verifyMulti([self::root('r1', self::good(['operator' => 'a'])), self::root('r2', self::good(['operator' => 'b']))], 2);
        self::assertSame(['ok' => false, 'reason' => "multi-root attestation identity conflict: roots 'r1' and 'r2' disagree on operator"], $r);
    }

    // ---- the fail-closed catch ------------------------------------------------------------------------------------------------------------

    /** An error outside a root's own verifier (here the id turning out unprintable after construction) fails the whole verifier closed. */
    public function testAnErrorOutsideARootFailsClosed(): void
    {
        foreach (['boom' => 'boom', '' => 'unknown'] as $msg => $shown) {
            $root = self::root('a', static fn(): Obj => Obj::of(['ok' => true, 'bound' => true, 'measured' => Obj::of(['model_id' => 'm']), 'hostAsserted' => Obj::of(['k' => 1])]));
            $v = Attestation::createMultiRootVerifier(Obj::of(['threshold' => 1, 'roots' => [$root]]));
            $root->set('id', new class((string)$msg) {
                public function __construct(private readonly string $m)
                {
                }

                public function __toString(): string
                {
                    throw new \RuntimeException($this->m);
                }
            });
            self::assertSame(['ok' => false, 'reason' => 'multi-root attestation error (fail closed): ' . $shown], $v(new Obj()));
        }
    }

    // ---- anchoring -------------------------------------------------------------------------------------------------------------------------------

    private static function evidence(): Obj
    {
        return Obj::of(['binding' => Obj::of(['holderPub' => 'H', 'grantRef' => 'G', 'epoch' => 1, 'nonce' => 'n']),
            'identity' => Obj::of(['model_id' => 'm', 'weights_digest' => 'w', 'weights_measured' => true, 'runtime_measurement' => 'r', 'operator' => 'o']),
            'rootIds' => ['a'], 'suite' => 's', 'verifiedAt' => 5]);
    }

    private static function guardian(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/att/guardian7', true));
    }

    /** No ledger is a refusal with its message, whatever else is given. */
    public function testAnchoringWithoutALedgerThrows(): void
    {
        self::assertSame('RuntimeException|attestation anchoring (fail closed): no transparency ledger available',
            self::thrown(static fn() => Attestation::anchorEvidence(self::evidence(), null)));
    }

    /** Anchoring is not required by default, and required anchoring needs a guardian secret. */
    public function testRequiredIsOffByDefault(): void
    {
        $ledger = new TransparencyLedger('p');
        $out = Attestation::anchorEvidence(self::evidence(), $ledger);
        self::assertSame(['index', 'commit'], array_keys($out));
        self::assertSame(Attestation::evidenceDigest(self::evidence()), $out['commit']);
        self::assertSame(1, $ledger->size());
        self::assertSame('RuntimeException|attestation anchoring (fail closed): required anchoring needs a guardian secret to sign the tree head',
            self::thrown(static fn() => Attestation::anchorEvidence(self::evidence(), new TransparencyLedger('p'), null, null, null, null, null, true)));
    }

    /**
     * Without an injected clock the signed tree head is stamped with the wall clock in whole epoch milliseconds. Two heads are taken at
     * distinct microseconds less than 1 ms apart, so at most one of the two readings falls on a whole millisecond: an unfloored clock
     * shows a fraction on the other one every time (the pair is retried until it fits in the window; two signatures take well under 1 ms).
     */
    public function testTheTreeHeadDefaultClock(): void
    {
        for ($attempt = 0; $attempt < 200; $attempt++) {
            $ledger = new TransparencyLedger('p');
            $t0 = \microtime(true);
            $a = Attestation::anchorEvidence(self::evidence(), $ledger, self::guardian());
            $mid = \microtime(true);
            while (\microtime(true) <= $mid) {
                // spin past the first reading's microsecond
            }
            $b = Attestation::anchorEvidence(self::evidence(), $ledger, self::guardian());
            $t1 = \microtime(true);
            foreach ([$a, $b] as $out) {
                self::assertArrayHasKey('sth', $out);
                $ts = Js::num($out['sth']->get('timestamp'));
                self::assertEqualsWithDelta(microtime(true) * 1000, $ts, 60000.0);
                self::assertSame(floor($ts), $ts);
            }
            if ($t1 - $t0 < 0.0009) {
                break;
            }
        }
        self::assertLessThan(0.0009, $t1 - $t0, 'two tree heads were signed inside one millisecond');
    }

    /** A tree-head signing failure is swallowed unless anchoring is required, and then it throws with the cause. */
    public function testASigningFailureThrowsOnlyWhenRequired(): void
    {
        $want = 'RuntimeException|attestation anchoring (fail closed): tree-head signing failed: ml-dsa-65 needs a post-quantum key pair';
        self::assertSame($want, self::thrown(static fn() => Attestation::anchorEvidence(self::evidence(), new TransparencyLedger('p'), self::guardian(), 'ml-dsa-65', null, null, null, true)));
        $out = Attestation::anchorEvidence(self::evidence(), new TransparencyLedger('p'), self::guardian(), 'ml-dsa-65');
        self::assertSame(['index', 'commit'], array_keys($out));
    }
}
