<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The grant envelope's check order, the signer-key refusals and the provenance header size limit. */
final class AgentEnvelopeKillTest extends TestCase
{
    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function refuses(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            self::assertInstanceOf(\InvalidArgumentException::class, $e);
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no exception: $msg");
    }

    public function testEnvelopeChecksRunInTheReferenceOrder(): void
    {
        $mint = static fn(array $over) => Sign::mintGrant(self::kp(1), self::kp(2)->public,
            $over + ['predicates' => [['verb' => 'v', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()], 'g', 's');
        $texts = [
            'risk_policy' => 'risk_policy must be an object',
            'units' => 'units must be an object',
            'tighten' => 'tighten must be an array',
            'template_ref' => 'template_ref must be an object',
            'actions' => 'actions must be an object',
            'provenance' => 'provenance must be an object',
            'model_polarity' => "model_polarity must be 'legacy' when present",
        ];
        $keys = array_keys($texts);
        foreach ($keys as $i => $k) {
            self::refuses("mintGrant: {$texts[$k]}", static fn() => $mint([$k => 'x']));
            if ($i + 1 < count($keys)) {
                // two bad members: the earlier check (envelope.ts mintGrant order) decides the reason
                self::refuses("mintGrant: {$texts[$k]}", static fn() => $mint([$k => 'x', $keys[$i + 1] => 'x']));
            }
        }
    }

    public function testSignerKeyRefusals(): void
    {
        self::refuses('ed25519 needs an Ed25519 key pair', static fn() => Sign::signWithSuite(null, null, null, 'm'));
        self::refuses('ed25519 needs an Ed25519 key pair', static fn() => Sign::signWithSuite('ed25519', null, null, 'm'));
        $sig = Sign::signWithSuite(null, self::kp(3), null, 'm');
        self::assertSame(['sig'], array_keys($sig));
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('ML-DSA-65 needs OpenSSL >= 3.5 over FFI');
        }
        $pq = new PqKeyPair('ML-DSA-65');
        self::refuses('hybrid-ed25519-ml-dsa-65 needs an Ed25519 key pair', static fn() => Sign::signWithSuite('hybrid-ed25519-ml-dsa-65', null, $pq, 'm'));
        self::assertSame(['sig'], array_keys(Sign::signWithSuite('ml-dsa-65', null, $pq, 'm')));
        self::assertSame(['sig', 'pq_sig'], array_keys(Sign::signWithSuite('hybrid-ed25519-ml-dsa-65', self::kp(3), $pq, 'm')));
    }

    public function testProvenanceHeaderFitsUpToTheLimit(): void
    {
        $pc = Obj::of(['a' => 'b']);
        // {"x":"<n>"} is n + 8 bytes; 6144 bytes encode to exactly 8192 base64url characters, 6145 to 8194
        $fit = Sign::headers($pc, [], null, null, Obj::of(['x' => str_repeat('a', 6136)]));
        self::assertSame(['PCA-Action', ArgProvenance::HEADER], array_keys($fit));
        self::assertSame(Sign::PROVENANCE_HEADER_MAX, strlen($fit[ArgProvenance::HEADER]));
        self::assertSame(['PCA-Action'], array_keys(Sign::headers($pc, [], null, null, Obj::of(['x' => str_repeat('a', 6137)]))));
    }
}
