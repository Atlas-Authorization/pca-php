<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sandbox;
use PHPUnit\Framework\TestCase;

/** Sandbox refusal paths: receipt/needs shapes, authorization binding, OS policy shapes, runtime-class claims, attestation trust and the egress address rule. */
final class CoreSurvivorKill27SandboxTest extends TestCase
{
    private static function throws(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        return ['none', ''];
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/k27-sandbox', true);
    }

    private static function attestor(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())));
    }

    private static function claim(array $over = []): Obj
    {
        $c = ['class' => 'os_confined', 'passport_digest' => 'P', 'evidence_digest' => 'E', 'iat' => 100, 'exp' => 200];
        foreach ($over as $k => $v) {
            $c[$k] = $v;
        }
        return Sandbox::signRuntimeClaim(self::seed(), sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())), Obj::of($c));
    }

    private static function trust(array $over = []): Obj
    {
        $t = ['pinnedAttestors' => [self::attestor()], 'passportDigest' => 'P', 'verifiedEvidenceDigests' => ['E'], 'now' => 150];
        foreach ($over as $k => $v) {
            $t[$k] = $v;
        }
        return Obj::of($t);
    }

    /** verifyReceiptChain and policyFromNeeds refuse non-lists and null entries with their own TypeErrors. */
    public function testIterableRefusals(): void
    {
        $this->assertSame(['TypeError', 'receipts is not iterable'], self::throws(static fn() => Sandbox::verifyReceiptChain('x')));
        $this->assertSame(['TypeError', 'receipt is null'], self::throws(static fn() => Sandbox::verifyReceiptChain([null])));
        $this->assertSame(['TypeError', 'needs is not iterable'], self::throws(static fn() => Sandbox::policyFromNeeds('x')));
        $this->assertSame(['TypeError', 'not iterable'], self::throws(static fn() => Sandbox::policyFromNeeds([Obj::of(['fs' => 5])])));
        $this->assertSame(['InvalidArgumentException', 'bad_path'], self::throws(static fn() => Sandbox::policyFromNeeds([Obj::of(['fs' => 'ab'])])));
        $this->assertSame(['TypeError', 'fs entry is null'], self::throws(static fn() => Sandbox::policyFromNeeds([Obj::of(['fs' => [null]])])));
        $this->assertSame(['TypeError', 'net entry is null'], self::throws(static fn() => Sandbox::policyFromNeeds([Obj::of(['net' => [null]])])));
    }

    /** A net need without a host names the host "undefined", as the reference's String(undefined) does. */
    public function testNetNeedWithoutHost(): void
    {
        $p = Sandbox::policyFromNeeds([Obj::of(['net' => [Obj::of(['port' => 443])]])], 3128);
        $this->assertSame(['undefined:443'], $p->get('net')->get('hosts'));
    }

    /** A result bound to params that cannot be hashed never authorizes. */
    public function testUnhashableParamsNeverAuthorize(): void
    {
        $result = Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => 'v', 'resource' => 'r', 'params_digest' => Pca::hashCanonical(Obj::of(['a' => 'b']))])]);
        $this->assertTrue(Sandbox::isAuthorizedFor($result, Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['a' => 'b'])])));
        $this->assertFalse(Sandbox::isAuthorizedFor($result, Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['a' => new \stdClass()])])));
    }

    /** Policy profiles are Obj trees all the way down, and a numeric-looking path keeps its string form and its rights. */
    public function testPolicyShapes(): void
    {
        $p = Obj::of(['v' => 1, 'fs' => Obj::of(['read' => ['5'], 'write' => [], 'exec' => []]), 'net' => Obj::of(['proxy' => null, 'hosts' => []])]);
        $this->assertInstanceOf(Obj::class, Sandbox::seccompProfile($p)->get('syscalls')[0]);
        $rule = Sandbox::landlockRuleset($p)->get('rules')->get('fs')[0];
        $this->assertSame('5', $rule->get('path'));
        $this->assertSame(['LANDLOCK_ACCESS_FS_READ_FILE', 'LANDLOCK_ACCESS_FS_READ_DIR'], $rule->get('access'));
    }

    /** signRuntimeClaim refuses a key that is not a 32-byte seed. */
    public function testSignRefusesShortKey(): void
    {
        $this->assertSame(['InvalidArgumentException', 'secret key must be a 32-byte seed'], self::throws(static fn() => Sandbox::signRuntimeClaim('short', 'pk', new Obj())));
    }

    /** A signed claim is refused for a wrong version or a non-Obj value; digests may be 128 UTF-16 units but not 129; a string trust list matches by substring. */
    public function testRuntimeClaimRules(): void
    {
        $this->assertSame('os_confined', Sandbox::verifiedRuntimeClass(self::claim(), self::trust()));
        $this->assertSame('none', Sandbox::verifiedRuntimeClass(self::claim(['v' => 2]), self::trust()));
        $c = self::claim();
        $duck = new class ($c) {
            public function __construct(private Obj $o)
            {
            }

            public function keys(): array
            {
                return $this->o->keys();
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function without(string ...$k): Obj
            {
                return $this->o->without(...$k);
            }
        };
        $this->assertSame('none', Sandbox::verifiedRuntimeClass($duck, self::trust()));
        $this->assertSame('os_confined', Sandbox::verifiedRuntimeClass($c, self::trust(['pinnedAttestors' => 'x' . self::attestor() . 'y'])));
        foreach (['passport_digest' => 'passportDigest', 'evidence_digest' => 'verifiedEvidenceDigests'] as $k => $t) {
            foreach ([128 => 'os_confined', 129 => 'none'] as $n => $want) {
                $d = str_repeat('d', $n);
                $this->assertSame($want, Sandbox::verifiedRuntimeClass(self::claim([$k => $d]), self::trust([$t => $t === 'passportDigest' ? $d : [$d]])), "$k $n");
            }
        }
    }

    /** The verifier is handed the attestation document; only then is its digest admitted. */
    public function testTrustFromAttestationPassesTheDocument(): void
    {
        $t = Sandbox::trustFromAttestation(['document' => 'doc', 'nowMs' => 1, 'verifier' => static fn(Obj $in): array => $in->get('document') === 'doc' ? ['ok' => true, 'bound' => true] : ['ok' => false]]);
        $this->assertSame([Sandbox::evidenceDigest('doc')], $t->get('verifiedEvidenceDigests'));
    }

    /** IPv4-mapped, compatible and NAT64 addresses follow the embedded IPv4 only when the whole prefix matches; anything else outside 2000::/3 is private. */
    public function testEmbeddedIpv4Classification(): void
    {
        $cases = [
            '::ffff:8.8.8.8' => false, '64:ff9b::8.8.8.8' => false, '::ffff:172.16.0.1' => true, '::ffff:169.255.0.1' => false,
            '0:1::ffff:808:808' => true, '0:0:1::ffff:808:808' => true, '0:0:0:1:0:ffff:808:808' => true, '0:0:0:0:1:ffff:808:808' => true,
            '64:ff9b:1::808:808' => true, '64:ff9b:0:1::808:808' => true, '64:ff9b:0:0:1:0:808:808' => true, '64:ff9b:0:0:0:1:808:808' => true,
            '64:1::808:808' => true, '::1:808:808' => true,
        ];
        foreach ($cases as $ip => $private) {
            $this->assertSame($private, Sandbox::isPrivateAddress($ip), $ip);
        }
    }

    /** The probe tool is a well-formed core module (magic, version, final end opcode). */
    public function testProbeToolBytes(): void
    {
        $b = Sandbox::buildProbeTool();
        $this->assertSame("\0asm\x01\0\0\0", substr($b, 0, 8));
        $this->assertSame("\x0b", substr($b, -1));
    }
}
