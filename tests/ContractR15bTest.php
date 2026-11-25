<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentPolicy;
use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Oidc;
use Atlas\Pca\OidcVerificationError;
use Atlas\Pca\Spiffe;
use Atlas\Pca\SpiffeError;
use PHPUnit\Framework\TestCase;

/** Options a caller supplies are refused as configuration before any token is read; an empty or valueless model is refused, never read as "nothing to check". */
final class ContractR15bTest extends TestCase
{
    private static function oidcCode(array $extra): string
    {
        try {
            Oidc::verifyIdToken('a.b.c', ['issuer' => 'https://idp.example', 'audience' => 'a'] + $extra);
        } catch (OidcVerificationError $e) {
            return $e->codeName;
        }
        return 'none';
    }

    public function testOidcRefusesAHostileSkewToleranceAsConfiguration(): void
    {
        foreach ([-1, NAN, INF, true, false, '', 'x', [], ['x']] as $bad) {
            self::assertSame('config', self::oidcCode(['clockToleranceSec' => $bad]), 'clockToleranceSec ' . var_export($bad, true));
        }
    }

    public function testOidcRefusesANegativeOrNonNumericTokenAgeAsConfiguration(): void
    {
        foreach ([-1, NAN, 'x', ['x'], new \stdClass()] as $bad) {
            self::assertSame('config', self::oidcCode(['maxTokenAgeSec' => $bad]), 'maxTokenAgeSec ' . var_export($bad, true));
        }
        // JS `x >= 0` lets these through the configuration gate (the token check refuses them later)
        foreach ([0, 1.5, true, false, '', []] as $ok) {
            self::assertNotSame('config', self::oidcCode(['maxTokenAgeSec' => $ok]), 'maxTokenAgeSec ' . var_export($ok, true));
        }
    }

    public function testJwtSvidRefusesAHostileToleranceOrClockUpFront(): void
    {
        foreach ([['clockTolerance' => -1], ['clockTolerance' => NAN], ['nowMs' => NAN], ['nowMs' => INF]] as $extra) {
            try {
                Spiffe::verifyJwtSvid('a.b.c', ['trustDomain' => 'example.org', 'audience' => 'api'] + $extra);
                self::fail('accepted ' . json_encode(array_map('strval', $extra)));
            } catch (SpiffeError $e) {
                self::assertSame('malformed_token', $e->codeName);
            }
        }
    }

    public function testAnOmegaWithNoVerbHasNothingToSample(): void
    {
        $this->expectException(\TypeError::class);
        IntentOmega::sampleOutcome(Obj::of(['v' => 1, 'verbs' => [], 'approximate' => []]), static fn(): float => 0.5);
    }

    public function testACategoricalDimensionWithoutValuesIsRefused(): void
    {
        $j = Obj::of(['approximate' => [], 'verbs' => [Obj::of(['verb' => 'v', 'reversibility' => 'reversible', 'w' => 1,
            'dims' => [Obj::of(['kind' => 'cat', 'path' => 'action.params.y', 'values' => []])]])]]);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("categorical dimension 'action.params.y' has no values");
        IntentMapKit::omegaFromJSON($j);
    }

    public function testAnAdmitterBuiltFromAnAssociativeArrayPolicyReadsIt(): void
    {
        $pred = Obj::of(['verb' => 'v.a', 'resource' => '*', 'where' => [Obj::of(['field' => 'action.params.a', 'op' => 'lte', 'value' => new Num('5')])]]);
        $adm = IntentPolicy::admitter(['predicates' => [$pred], 'caveats' => []]);
        $vs = Obj::of(['verb' => 'v.a', 'reversibility' => 'reversible', 'dims' => []]);
        $at = static fn(int $a): Obj => Obj::of(['verb' => 'v.a', 'values' => Obj::of(['action.params.a' => $a])]);
        self::assertTrue($adm->admits($vs, $at(3)), 'inside the policy');
        self::assertFalse($adm->admits($vs, $at(9)), 'outside the policy');
    }

    public function testRemovingATreeRemovesHiddenFilesAndRaisesNothingForAMissingOne(): void
    {
        $dir = sys_get_temp_dir() . '/pca-rmtree-' . bin2hex(random_bytes(6));
        mkdir($dir . '/sub', 0700, true);
        file_put_contents($dir . '/.hidden', 'x');
        file_put_contents($dir . '/sub/.also', 'y');
        file_put_contents($dir . '/plain', 'z');
        $warnings = 0;
        set_error_handler(static function () use (&$warnings): bool {
            $warnings++;
            return true;
        });
        try {
            MpcNetCerts::rmTree($dir);
            MpcNetCerts::rmTree($dir); // the destructor that runs after the cleanup
        } finally {
            restore_error_handler();
        }
        self::assertDirectoryDoesNotExist($dir);
        self::assertSame(0, $warnings);
    }
}
