<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\CaveatLang;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The caveat language v2 (K1) and the K1 request headers against the TS reference: test-data/k05-caveatlang.json.gz. */
final class K05CaveatLangDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-caveatlang.json.gz';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'spiffeIdError' => fn(array $a) => CaveatLang::spiffeIdError($a[0]),
            'needsDischargeError' => fn(array $a) => CaveatLang::needsDischargeError($a[0]),
            'dischargeShapeError' => fn(array $a) => CaveatLang::dischargeShapeError($a[0]),
            'narrowShapeError' => fn(array $a) => CaveatLang::narrowShapeError($a[0]),
            'maxUsesError' => fn(array $a) => CaveatLang::maxUsesError($a[0]),
            'maxUsesSlotKey' => fn(array $a) => CaveatLang::maxUsesSlotKey($a[0], $a[1], $a[2]->int()),
            'spiffeBoundError' => fn(array $a) => CaveatLang::spiffeBoundError($a[0]),
            'deriveError' => fn(array $a) => CaveatLang::deriveError($a[0]),
            'evaluateDerive' => function (array $a) {
                $inp = [];
                foreach ($a[1]->keys() as $key) {
                    $inp[$key] = $a[1]->get($key);
                }
                return CaveatLang::evaluateDerive($a[0], $inp);
            },
            'verifyDischarge' => fn(array $a) => CaveatLang::verifyDischarge($a[0], $a[1], $a[2]),
            'verifyNarrow' => fn(array $a) => CaveatLang::verifyNarrow($a[0], $a[1], $a[2], $a[3]),
            'boundCaveats' => fn(array $a) => CaveatLang::boundCaveats($a[0], $a[1] ?? null),
            'dischargeRequests' => fn() => [K05::SKIP, 'not in the PHP port (discharge requests are minted by the TS issuer side)'],
            'evaluateK1' => fn(array $a) => CaveatLang::evaluateK1($a[0], $a[1] ?? null, $a[2] ?? null, $a[3]),
            'evaluateCaveatsK1' => function (array $a) {
                [$allow, $failed] = CaveatLang::evaluateCaveatsK1($a[0], $a[1] ?? null, $a[2] ?? null, $a[3]);
                return ['allow' => $allow, 'failed' => $failed];
            },
            'presentedK1' => function (array $a) {
                $r = CaveatLang::presentedK1($a[0]);
                return $r['ok'] ? $r : ['ok' => false]; // the reference projection drops the reason
            },
        ]);
    }
}
