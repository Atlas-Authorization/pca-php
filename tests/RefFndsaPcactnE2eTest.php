<?php
declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Fndsa;
use Atlas\Pca\FndsaNative;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * End to end FN-DSA PCActn leaf (fn-dsa-512 / fn-dsa-1024): the shared fixture's `valid` body is signed through the public sign path
 * (Sign::signPcactn with a PqKeyPair derived from the fixture labels) and must equal the reference bytes; every fixture case goes through
 * Pca::verifyPcactnCore and must match expect_allow; with no backend registered every case denies (the valid one with unsupported_suite).
 * The libfndsa cases need ext-ffi and ATLAS_PCA_LIBFNDSA; ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping.
 */
final class RefFndsaPcactnE2eTest extends TestCase
{
    protected function setUp(): void
    {
        Fndsa::resetFalconBackend();
    }

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    /** @return list<Obj> */
    private static function cases(): array
    {
        $doc = Json::parseStrict((string) file_get_contents(__DIR__ . '/../test-data/ref-fndsa-pcactn.json'), true);
        return array_values($doc->get('cases'));
    }

    public static function allCases(): array
    {
        $o = [];
        foreach (self::cases() as $c) {
            $o[$c->get('name')] = [$c->get('name')];
        }
        return $o;
    }

    public static function validCases(): array
    {
        return array_filter(self::allCases(), static fn(string $k): bool => str_ends_with($k, '/valid'), ARRAY_FILTER_USE_KEY);
    }

    private static function find(string $name): Obj
    {
        foreach (self::cases() as $c) {
            if ($c->get('name') === $name) {
                return $c;
            }
        }
        throw new \LogicException("fixture case $name");
    }

    private function real(): void
    {
        if (!FndsaNative::available()) {
            if (getenv('ATLAS_PCA_LIBFNDSA_REQUIRED') === '1') {
                $this->fail('libfndsa must load (ATLAS_PCA_LIBFNDSA, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA)');
        }
        Fndsa::setFalconBackend(FndsaNative::backend());
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    /** @return array{allow:bool,reason?:string} */
    private static function verify(Obj $c): array
    {
        $now = $c->get('now_epoch');
        return Pca::verifyPcactnCore($c->get('pcactn'), $c->get('grant'), $now instanceof Num ? (int) $now->float() : (int) $now,
            $c->get('audience'), insecureSkipPlanRootCheck: true);
    }

    #[DataProvider('validCases')]
    public function testSignsTheReferenceBytes(string $name): void
    {
        $this->real();
        $c = self::find($name);
        $l = $c->get('key_labels');
        $pq = new PqKeyPair(strtoupper($c->get('alg')), self::seed($l->get('fndsa_keygen')), self::seed($l->get('fndsa_sign_seed')));
        $this->assertSame($c->get('pq_pk'), $pq->public);
        $signed = Sign::signPcactn($c->get('body'), new KeyPair(self::seed($l->get('agent_ed25519'))), $c->get('alg'), $pq);
        $this->assertSame(Json::canonicalizeLenient($c->get('pcactn')), Json::canonicalizeLenient($signed));
        $again = Sign::signPcactn($c->get('body'), new KeyPair(self::seed($l->get('agent_ed25519'))), $c->get('alg'), $pq);
        $this->assertSame($signed->get('sig'), $again->get('sig'));
    }

    #[DataProvider('allCases')]
    public function testVerifyMatchesExpectation(string $name): void
    {
        $this->real();
        $c = self::find($name);
        $v = self::verify($c);
        $this->assertSame($c->get('expect_allow'), $v['allow'], $name . ' ' . ($v['reason'] ?? ''));
    }

    #[DataProvider('allCases')]
    public function testNoBackendNeverAllows(string $name): void
    {
        $c = self::find($name);
        $v = self::verify($c);
        $this->assertFalse($v['allow'], $name);
        if (str_ends_with($name, '/valid')) {
            $this->assertStringContainsString('unsupported_suite', $v['reason'] ?? '', $name);
        }
    }

    public function testSigningWithoutBackendIsRefused(): void
    {
        $this->expectException(\Atlas\Pca\UnsupportedSigner::class);
        new PqKeyPair('FN-DSA-512', str_repeat("\1", 32));
    }
}
