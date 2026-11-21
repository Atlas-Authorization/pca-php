<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\PcaTesting;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The testing kit (acceptance constants and route mapping, fake verifier, tamper, in-memory state store) against the TS reference: test-data/ref-testing.json.gz. */
final class RefTestingDifferentialTest extends TestCase
{
    private const FILE = 'ref-testing.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'consts' => fn(array $a) => Obj::of(['aud' => PcaTesting::ADAPTER_ACCEPTANCE_AUDIENCE, 'expected' => PcaTesting::adapterAcceptanceExpected()]),
            'acceptanceOperation' => fn(array $a) => PcaTesting::acceptanceOperation($a[0]),
            'fakeVerifyAllow' => fn(array $a) => PcaTesting::fakeVerify($a[0], $a[1] ?? null)['allow'],
            'expectVerifies' => fn(array $a) => PcaTesting::expectVerifies($a[0], $a[1] ?? null)['allow'],
            'expectDenied' => fn(array $a) => PcaTesting::expectDenied($a[0], $a[1] ?? null)['allow'],
            'tamper' => fn(array $a) => PcaTesting::tamper($a[0], $a[1]),
            'memorySession' => function (array $a) {
                $s = PcaTesting::memoryStateStore();
                $out = [];
                foreach ($a[0] as $op) {
                    if ($op[0] === 'put') {
                        $s->put($op[1], $op[2]);
                    } else {
                        $out[] = $s->get($op[1]);
                    }
                }
                return $out;
            },
        ]);
    }
}
