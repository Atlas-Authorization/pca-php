<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attestation.php';

use Atlas\Pca\Attestation;
use Atlas\Pca\DevAttestor;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** verifyAttestation and its hook, end to end on a signed software document and on a stub hardware verifier. */
final class AttestSurvivorKill7AttestationVerifyTest extends TestCase
{
    private const NOW = 1800000000000;
    private const N = '0123456789abcdef0123456789abcdef';
    private const RISK = '"risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,"kappa":1,"lambda":0,"rho":0,"bMax":0}';

    private static function kp(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/att/verify7', true));
    }

    private static function doc(array $over = []): Obj
    {
        return (new DevAttestor(self::kp()))->attest(Obj::of($over + ['model_id' => 'm1', 'weights_digest' => 'w1', 'runtime_measurement' => 'rt1',
            'operator' => 'op1', 'nonce' => self::N, 'issued_at' => self::NOW - 1000, 'expires_at' => self::NOW + 60000, 'holder_pub' => 'H',
            'grant_ref' => 'G', 'epoch' => 1]));
    }

    private static function expected(int $issued = self::NOW - 1000): Obj
    {
        return Obj::of(['holderPub' => 'H', 'grantRef' => 'G', 'epoch' => 1, 'nonce' => self::N, 'nonceIssuedAt' => $issued]);
    }

    private static function ctx(?string $agentBinding = null): Obj
    {
        $grant = $agentBinding === null ? new Obj() : Json::parseLax('{"id":"g1","caveats":[{"type":"envelope","goal_commit":"x","predicates":[{"verb":"*","where":[]}],'
            . '"caveats":[],"agent_binding":' . $agentBinding . ',' . self::RISK . '}]}');
        return Obj::of(['pcactn' => Obj::of(['grant_ref' => 'G', 'attestation' => Obj::of(['epoch' => 1, 'quote_digest' => self::N])]), 'grant' => $grant]);
    }

    private static function verify(?Obj $doc = null, ?string $agentBinding = null, array $extra = [], ?Obj $expected = null): array
    {
        $in = Obj::of(['document' => $doc ?? self::doc(), 'ctx' => self::ctx($agentBinding), 'expected' => $expected ?? self::expected(), 'nowMs' => self::NOW,
            'trustedAttestorKeys' => [self::kp()->public]]);
        foreach ($extra as $k => $v) {
            $in->set($k, $v);
        }
        return Attestation::verifyAttestation($in);
    }

    private static function reason(array $r): string
    {
        self::assertFalse($r['ok']);
        return (string)$r['reason'];
    }

    private static function measured(): Obj
    {
        return Obj::of(['model_id' => 'm1', 'weights_digest' => 'w1', 'runtime_measurement' => 'rt1', 'operator' => 'op1']);
    }

    /** Control: the base fixture verifies, so every refusal below is caused by the one thing it changes. */
    public function testTheBaseDocumentVerifies(): void
    {
        $r = self::verify();
        self::assertTrue($r['ok'], (string)($r['reason'] ?? ''));
        self::assertTrue($r['bound']);
        self::assertSame('m1', $r['identity']->get('model_id'));
    }

    /** The clock skew is floored at 0 (a fractional skew is not rounded up to 1 ms): a nonce issued 1 ms ahead is in the future under 0.5 ms skew. */
    public function testFractionalSkewIsNotRoundedUp(): void
    {
        self::assertSame('nonce issued in the future', self::reason(self::verify(null, null, ['clockSkewMs' => 0.5], self::expected(self::NOW + 1))));
        self::assertSame('nonce issued in the future', self::reason(self::verify(null, null, ['clockSkewMs' => -5], self::expected(self::NOW + 1))));
        self::assertTrue(self::verify(null, null, ['clockSkewMs' => 1], self::expected(self::NOW + 1))['ok']);
    }

    /** A zero or negative maxNonceAgeMs falls back to the 5-minute default, which also caps any larger value. */
    public function testMaxNonceAgeFallsBackAndIsCapped(): void
    {
        self::assertTrue(self::verify(null, null, ['maxNonceAgeMs' => 0])['ok']);
        self::assertTrue(self::verify(null, null, ['maxNonceAgeMs' => -5])['ok']);
        self::assertSame('attestation nonce expired (stale quote)', self::reason(self::verify(null, null, ['maxNonceAgeMs' => 1000000000], self::expected(self::NOW - 400000))));
    }

    /** The grant's agent_binding is read from its envelope and enforced. */
    public function testTheEnvelopeAgentBindingIsEnforced(): void
    {
        self::assertSame('model_id m1 not in model_allowlist', self::reason(self::verify(null, '{"model_allowlist":["other"]}')));
        self::assertSame('agent_binding.require_hardware: no hardware verifier is configured (fail closed)', self::reason(self::verify(null, '{"require_hardware":true}')));
        self::assertTrue(self::verify(null, '{"model_allowlist":["m1"]}')['ok']);
    }

    /** The software identity carries the system-prompt and tool-manifest digests, and the allowlists see them. */
    public function testSoftwareIdentityCarriesPromptAndToolDigests(): void
    {
        $d = self::doc(['system_prompt_digest' => 'sp1', 'tool_manifest_digest' => 'tm1']);
        $r = self::verify($d, '{"system_prompt_allowlist":["sp1"],"tool_manifest_allowlist":["tm1"]}');
        self::assertTrue($r['ok'], (string)($r['reason'] ?? ''));
        self::assertSame('sp1', $r['identity']->get('system_prompt_digest'));
        self::assertSame('tm1', $r['identity']->get('tool_manifest_digest'));
        $plain = self::verify();
        self::assertFalse($plain['identity']->has('system_prompt_digest'));
        self::assertFalse($plain['identity']->has('tool_manifest_digest'));
    }

    /** A pinned post-quantum key never stands in for the signature: a bad signature under a pinned key is still refused. */
    public function testAPinnedPqKeyStillNeedsAValidSignature(): void
    {
        $d = self::doc();
        $d->set('alg', 'ml-dsa-65');
        $d->set('pq_pk', 'AAAA');
        $want = 'attestation signature does not verify';
        self::assertSame($want, self::reason(self::verify($d, null, ['pqPins' => Obj::of([self::kp()->public => 'AAAA'])])));
        self::assertSame($want, self::reason(self::verify($d, null, ['pqPins' => Obj::of([self::kp()->public => 'BBBB'])])));
        self::assertSame($want, self::reason(self::verify($d)));
    }

    private static function hwDoc(): Obj
    {
        return Obj::of(['nonce' => self::N, 'mode' => 'hardware']);
    }

    private static function hwIn(\Closure $hw, ?Obj $expected = null): Obj
    {
        return Obj::of(['document' => self::hwDoc(), 'ctx' => self::ctx(), 'expected' => $expected ?? self::expected(), 'nowMs' => self::NOW,
            'trustedAttestorKeys' => [], 'hardware' => $hw]);
    }

    /** The hardware verifier receives the document, the context, the clock and the expected binding. */
    public function testHardwareVerifierGetsTheFullInput(): void
    {
        $got = null;
        $hw = static function (mixed $i) use (&$got): Obj {
            $got = $i;
            return Obj::of(['ok' => true, 'bound' => true, 'measured' => Obj::of(['model_id' => 'm1', 'weights_digest' => 'w1', 'runtime_measurement' => 'rt1', 'operator' => 'op1'])]);
        };
        $expected = self::expected();
        $in = self::hwIn($hw, $expected);
        $r = Attestation::verifyAttestation($in);
        self::assertTrue($r['ok'], (string)($r['reason'] ?? ''));
        self::assertSame('m1', $r['identity']->get('model_id'));
        self::assertSame(['document', 'ctx', 'nowMs', 'expected'], $got->keys());
        self::assertSame($in->get('document'), $got->get('document'));
        self::assertSame(self::NOW, $got->get('nowMs'));
        self::assertSame($expected, $got->get('expected'));
    }

    /** An exception anywhere in verification fails closed with the exception text, or "unknown" when it has none. */
    public function testAnExceptionFailsClosedWithItsText(): void
    {
        foreach (['boom' => 'boom', '' => 'unknown'] as $msg => $shown) {
            $r = Attestation::verifyAttestation(self::hwIn(static function () use ($msg): never {
                throw new \RuntimeException((string)$msg);
            }));
            self::assertSame(['ok' => false, 'present' => true, 'bound' => false, 'reason' => 'attestation verification error (fail closed): ' . $shown], $r);
        }
    }

    // ---- the hook ----------------------------------------------------------------------------------------------------------------

    /** A failing expectedBinding callback fails the hook closed with the exception text, or "unknown". */
    public function testTheHookFailsClosedWhenTheBindingCallbackThrows(): void
    {
        foreach (['boom' => 'boom', '' => 'unknown'] as $msg => $shown) {
            $hook = Attestation::createAttestationVerifier(Obj::of(['trustedAttestorKeys' => [], 'now' => static fn() => self::NOW,
                'expectedBinding' => static function () use ($msg): never {
                    throw new \RuntimeException((string)$msg);
                }]));
            self::assertSame(['enforced' => true, 'ok' => false, 'reason' => 'attestation verification error (fail closed): ' . $shown, 'present' => false, 'bound' => false],
                $hook(self::ctx()));
        }
    }

    /** Without an injected clock the hook passes the verifier the wall clock in whole epoch milliseconds. */
    public function testTheHookDefaultClockIsWholeEpochMilliseconds(): void
    {
        $got = null;
        $issued = (int)(microtime(true) * 1000) - 1000;
        $hook = Attestation::createAttestationVerifier(Obj::of(['trustedAttestorKeys' => [],
            'resolveDocument' => static fn() => self::hwDoc(),
            'expectedBinding' => static fn() => self::expected($issued),
            'hardware' => static function (mixed $i) use (&$got): Obj {
                $got = $i;
                return Obj::of(['ok' => false, 'reason' => 'stop']);
            }]));
        $r = $hook(self::ctx());
        self::assertSame('hardware attestation rejected: stop', $r['reason']);
        self::assertNotNull($got, 'the verifier reached the hardware verifier, so the clock agreed with the nonce issue time');
        self::assertIsInt($got->get('nowMs'));
        self::assertEqualsWithDelta(microtime(true) * 1000, $got->get('nowMs'), 60000.0);
    }
}
