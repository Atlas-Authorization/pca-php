<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestEatProvenance;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\SigstoreBundle;
use PHPUnit\Framework\TestCase;

/** The artifact discharge: the exact unsigned body, the gate refusal text, and issueArtifactDischarge's input checks, clock rounding and default nonce. */
final class AttestSurvivorKill7EatProvenanceTest extends TestCase
{
    private static ?Obj $case = null;

    /** The inputs of the corpus case issueArtifactDischarge/ok (a real Sigstore bundle that passes the gate). */
    private static function okInput(): array
    {
        if (!function_exists('sodium_crypto_sign_seed_keypair') || !extension_loaded('openssl')) {
            self::markTestSkipped('needs ext-sodium and ext-openssl');
        }
        if (self::$case === null) {
            foreach (gzfile(Base::path('ref-attest-eat-discharge.json.gz')) as $line) {
                if (str_starts_with($line, '{"fn":"issueArtifactDischarge"')) {
                    $c = Json::parseLax(rtrim(rtrim($line), ','));
                    if ($c->get('name') === 'issueArtifactDischarge/ok') {
                        self::$case = $c->get('args')[0];
                        break;
                    }
                }
            }
        }
        $o = self::$case ?? throw new \LogicException('corpus case issueArtifactDischarge/ok not found');
        return ['bundle' => $o->get('bundle'), 'roots' => SigstoreBundle::parseTrustedRoot($o->get('roots')), 'policy' => $o->get('policy'),
            'runtime' => $o->get('runtime'), 'request' => $o->get('request')->without(), 'now' => $o->get('now')->int(),
            'issuerKey' => new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $o->get('issuerKey')->get('seed')->get('$seed'), true))];
    }

    private static function nonce(): \Closure
    {
        return static fn(): string => str_repeat("\x01", 16);
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'no throw';
    }

    /** The unsigned body carries v 1, the request binding (its action_digest when present), the claims, iat, iat + ttl and the nonce. */
    public function testDischargeBodyShape(): void
    {
        $req = Obj::of(['caveat_id' => 'c', 'issuer' => 'i', 'cap_hash' => 'h', 'bind' => 'action', 'action_digest' => 'd', 'ttl_ms' => new Num('100')]);
        $b = AttestEatProvenance::provenanceDischargeBody($req, ['ok' => true, 'claims' => ['a' => 1]], 1000, 50, 'n');
        $this->assertSame(['v', 'kind', 'caveat_id', 'issuer', 'cap_hash', 'bind', 'action_digest', 'claims', 'iat', 'not_after', 'nonce'], $b->keys());
        $this->assertSame(1, $b->get('v'));
        $this->assertSame('pca-discharge', $b->get('kind'));
        $this->assertSame('d', $b->get('action_digest'));
        $this->assertSame(1, $b->get('claims')->get('a'));
        $this->assertSame(1000, $b->get('iat'));
        $this->assertSame(1050, $b->get('not_after'));
        $this->assertSame('n', $b->get('nonce'));
        $b = AttestEatProvenance::provenanceDischargeBody(Obj::of(['caveat_id' => 'c', 'bind' => 'chain_hop']), ['ok' => true, 'claims' => []], 1000, 50, 'n');
        $this->assertFalse($b->has('action_digest'));
        $this->assertSame(1050, $b->get('not_after'));
    }

    /** A gate that refused (or reports no ok at all) throws with its code, or '?'. */
    public function testRefusedGateThrowsWithItsCode(): void
    {
        $req = Obj::of(['caveat_id' => 'c']);
        $this->assertSame('InvalidArgumentException: provenanceDischargeBody: the provenance gate refused (x)',
            self::thrown(static fn() => AttestEatProvenance::provenanceDischargeBody($req, ['ok' => false, 'code' => 'x'], 1, 1, 'n')));
        $this->assertSame('InvalidArgumentException: provenanceDischargeBody: the provenance gate refused (?)',
            self::thrown(static fn() => AttestEatProvenance::provenanceDischargeBody($req, ['claims' => []], 1, 1, 'n')));
    }

    /** Without a nonce source the discharge nonce is 16 random bytes (22 base64url chars). */
    public function testDefaultNonceIsSixteenBytes(): void
    {
        $r = AttestEatProvenance::issueArtifactDischarge(self::okInput());
        $this->assertTrue($r['ok']);
        $this->assertSame(22, strlen($r['discharge']->get('nonce')));
    }

    /** The clock is floored to whole seconds: 600 ms before the integrated second is still in the future. */
    public function testClockIsFlooredToSeconds(): void
    {
        $i = self::okInput();
        $i['now'] = 1780347769600;
        $this->assertSame(['ok' => false, 'stage' => 'gate', 'code' => 'future'], AttestEatProvenance::issueArtifactDischarge($i, self::nonce()));
        $i['now'] = 1780347770000;
        $this->assertTrue(AttestEatProvenance::issueArtifactDischarge($i, self::nonce())['ok']); // control: the integrated second itself
    }

    /** A non-integer now, a missing request and a ttl that is neither given nor in the request are refused with their own messages. */
    public function testInputRefusals(): void
    {
        $i = self::okInput();
        $i['now'] = 1.5;
        $this->assertSame('InvalidArgumentException: issueArtifactDischarge: now must be an integer epoch ms',
            self::thrown(static fn() => AttestEatProvenance::issueArtifactDischarge($i, self::nonce())));
        $i = self::okInput();
        unset($i['request']);
        $this->assertSame('InvalidArgumentException: issueArtifactDischarge: request must be an object',
            self::thrown(static fn() => AttestEatProvenance::issueArtifactDischarge($i, self::nonce())));
        $i = self::okInput();
        $i['request'] = $i['request']->without('ttl_ms');
        $this->assertSame('InvalidArgumentException: issueArtifactDischarge: ttl_ms must be an integer',
            self::thrown(static fn() => AttestEatProvenance::issueArtifactDischarge($i, self::nonce())));
    }

    /** A request field that is null reaches the signer as an empty string, so the signer's own shape check decides (never a type error). */
    public function testNullRequestFieldsReachTheSignerAsStrings(): void
    {
        foreach (['caveat_id', 'issuer', 'cap_hash', 'bind'] as $k) {
            $i = self::okInput();
            $i['request']->set($k, null);
            try {
                $r = AttestEatProvenance::issueArtifactDischarge($i, self::nonce());
                $this->assertTrue($r['ok'], $k);
            } catch (\InvalidArgumentException $e) {
                $this->assertStringStartsWith('signDischarge: ', $e->getMessage(), $k);
            }
        }
    }
}
