<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FheOrigin;
use Atlas\Pca\FheRisk;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The pure parts of pca-fhe (quantization, gate policy, signed-claim and verdict-attestation layer) against the TS reference: test-data/ref-fhe.json.gz. */
final class RefFheDifferentialTest extends TestCase
{
    private const FILE = 'ref-fhe.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** @return list<string> */
    private static function strs(mixed $l): array
    {
        return array_map(static fn(mixed $s): string => (string) $s, is_array($l) ? $l : []);
    }

    private static function res(array $r): Obj
    {
        $o = new Obj();
        foreach ($r as $k => $v) {
            $o->set((string) $k, $v);
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'transformedInputs' => fn(array $a) => FheRisk::transformedInputs($a[0]),
            'quantizeRiskInputs' => fn(array $a) => count($a) === 1 ? FheRisk::quantizeRiskInputs($a[0]) : FheRisk::quantizeRiskInputs($a[0], $a[1]),
            'weightVector' => fn(array $a) => FheRisk::weightVector($a[0]),
            'fheRiskPolicy' => fn(array $a) => count($a) === 2 ? FheRisk::fheRiskPolicy($a[0], $a[1]) : FheRisk::fheRiskPolicy($a[0], $a[1], $a[2]),
            'plaintextVerdict' => fn(array $a) => FheRisk::plaintextVerdict($a[0], $a[1], $a[2]),
            'fromActn' => fn(array $a) => FheRisk::transformedInputs(FheRisk::riskInputsFromPCActn($a[0])),
            'binding' => fn(array $a) => FheRisk::bindingFromPCActn($a[0]),
            'sign' => fn(array $a) => FheOrigin::signRiskClaim($a[0], (string) Pca::unb64u($a[1]), (string) $a[2], Base::bytes($a[3])),
            'claimDigest' => fn(array $a) => FheOrigin::signedClaimDigest($a[0]),
            'verifyClaim' => function (array $a) {
                $e = $a[1];
                $used = array_fill_keys(self::strs($e->get('used')), true);
                $max = (int) $e->get('max')->float();
                $guard = static function (string $key) use (&$used, $max): bool {
                    if (isset($used[$key]) || count($used) >= $max) {
                        return false;
                    }
                    $used[$key] = true;
                    return true;
                };
                $r = FheOrigin::verifySignedRiskClaim($a[0], self::strs($e->get('trustedSigners')), (string) $e->get('context'), $e->get('binding'), $e->get('policy'), $guard);
                return $r['ok'] ? self::res(['ok' => true, 'claim' => $r['claim'], 'digest' => $r['digest']]) : self::res(['ok' => false, 'reason' => $r['reason']]);
            },
            'nonceGuard' => function (array $a) {
                $g = FheOrigin::memoryNonceGuard((int) $a[0]->float());
                return array_map(static fn(mixed $key): bool => $g((string) $key), $a[1]);
            },
            'attest' => fn(array $a) => FheOrigin::attestVerdict((string) Pca::unb64u($a[0]), $a[1], $a[2], $a[3] === true),
            'verifyAttest' => function (array $a) {
                $e = $a[1];
                $gate = $e->get('gate');
                $r = FheOrigin::verifyVerdictAttestation($a[0], self::strs($e->get('trustedHolders')), (string) $e->get('claimDigest'), $gate instanceof Obj ? $gate : null);
                return $r['ok'] ? self::res(['ok' => true, 'admit' => $r['admit']]) : self::res(['ok' => false, 'reason' => $r['reason']]);
            },
        ]);
    }
}
