<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ledger;
use Atlas\Pca\Mesh;
use Atlas\Pca\Parser;
use Atlas\Pca\RevocationStaleness;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The cross-domain agent mesh and its Merkle primitives against the TS reference: test-data/k05-mesh.json.gz. */
final class K05MeshDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-mesh.json.gz';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Mesh::class, $m))->invoke(null, ...$a);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'verifyMeshProof' => function (array $a) {
                $v = Mesh::verify($a[0], $a[1]);
                // the reference verdict carries hop only on a failure that names one
                $out = ['ok' => $v['ok']];
                if (isset($v['reason'])) {
                    $out['reason'] = $v['reason'];
                }
                if (!$v['ok'] && isset($v['hop']) && $v['hop'] >= 0) {
                    $out['hop'] = $v['hop'];
                }
                return $out;
            },
            'checkHeadAdvance' => function (array $a) {
                $r = self::priv('checkHeadAdvance', $a[0], $a[1], $a[2] ?? null);
                return $r === '' ? null : $r;
            },
            'verifyLedgerConsistency' => fn(array $a) => Ledger::verifyConsistency($a[0], $a[1], $a[2]),
            'verifyNonMembership' => fn(array $a) => RevocationStaleness::verifyNonMembership($a[0], $a[1], $a[2]),
            'effectiveAuthority' => function (array $a) {
                [$e, $err] = self::priv('effective', $a[0]);
                if ($err !== '') {
                    return ['error' => $err];
                }
                $out = ['prefixes' => $e['prefixes']];
                foreach ([['hasAct', 'actions'], ['hasAmount', 'maxAmount'], ['hasExp', 'expiresAt'], ['hasAud', 'audience'], ['hasHops', 'maxHops']] as [$has, $key]) {
                    if ($e[$has]) {
                        $out[$key] = $e[$key];
                    }
                }
                return $out;
            },
        ]);
    }

    /** a head pinned at size 0 (root '') advances: '' is checked as the RFC 9162 empty-tree root; a non-vacuous or mis-sized proof is refused. */
    public function testEmptyHeadAdvances(): void
    {
        $j = (new Parser('{"e":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":0,"root":"","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"n":{"domain":"wl-lCwz5vY4B0YK7sQ7uKb3cc2otR4xICIIfETuK5-A","size":3,"root":"CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow","rev_root":"JW0KqD54TdCDuAJBWPZxeGMeZji91AqTmqggkVvh8b8","rev_size":0,"timestamp":1800000000000},"ok":{"oldSize":0,"newSize":3,"path":[]},"path":{"oldSize":0,"newSize":3,"path":["CLtkc9aNjXFMls5Uddz62ktJoV2zAUnd3eyt05uysow"]},"old1":{"oldSize":1,"newSize":3,"path":[]}}', PHP_INT_MAX))->run();
        $adv = fn(mixed $pf) => self::priv('checkHeadAdvance', $j->get('e'), $j->get('n'), $pf);
        self::assertSame('', $adv($j->get('ok')));
        self::assertSame('consistency proof required for a larger head', $adv(null));
        self::assertSame('head is not consistent with the previous head (fork or rewrite)', $adv($j->get('path')));
        self::assertSame('consistency proof required for a larger head', $adv($j->get('old1')));
    }
}
