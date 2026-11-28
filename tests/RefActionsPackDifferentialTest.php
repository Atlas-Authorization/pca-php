<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsPack;
use Atlas\Pca\ActionsTransparency;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\TransparencyService;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsPack.php';
require_once __DIR__ . '/../src/ActionsTransparency.php';

/** Pack building, upgrade verification and the transparency log entries against the TS reference: ref-actions-pack and ref-actions-pack-log. */
final class RefActionsPackDifferentialTest extends TestCase
{
    public static function provide(): array
    {
        return Base::datasets('ref-actions-pack.json.gz') + self::logSets();
    }

    private static function logSets(): array
    {
        $out = [];
        foreach (Base::datasets('ref-actions-pack-log.json.gz') as $k => $v) {
            $out["log $k"] = $v;
        }
        return $out;
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/' . $label, true);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = \Atlas\Pca\Actions::coreRegistry();
        $none = static fn() => false;
        Base::run($file, $fn, $k, [
            'buildPack' => function (array $a) use ($core, $none) {
                $s = $a[0];
                return ActionsPack::buildPack($s->get('ns'), $s->get('version'), $s->get('stability'), $s->get('defs'), $s->get('source'), $s->get('kid'),
                    Base::bytes($a[1]), $core, $s->get('prev'), $s->get('shard'), $none);
            },
            'shardDefs' => fn(array $a) => ActionsPack::shardDefs($a[0], $a[1]),
            'verifyUpgrade' => fn(array $a) => ActionsPack::verifyUpgrade($a[0], $a[1], $a[2], $a[3], $a[4], $core, $none),
            'packStatementPayload' => fn(array $a) => ActionsTransparency::packStatementPayload($a[0]),
            'appendPackToLog' => function (array $a) {
                $spec = $a[1];
                $svc = new TransparencyService(['alg' => 'EdDSA', 'key' => Pca::unb64u($spec->get('tsSeed')), 'issuer' => 'ts']);
                for ($i = 0; $i < (int)($spec->get('preload')?->int() ?? 0); $i++) {
                    $svc->register(\Atlas\Pca\Scitt::signStatement(Obj::of(['i' => new \Atlas\Pca\Num((string)$i)]),
                        ['alg' => 'EdDSA', 'key' => self::seed('ref-actions-pack-log/other'), 'issuer' => 'other', 'subject' => "s$i"]));
                }
                $e = ActionsTransparency::appendPackToLog($a[0], $svc, ['alg' => 'EdDSA', 'key' => Pca::unb64u($spec->get('regSeed')), 'issuer' => $spec->get('issuer')]);
                return Obj::of(['statement' => Base::outBytes($e['statement']), 'receipt' => Base::outBytes($e['receipt']), 'index' => $e['index'], 'root' => $e['root']]);
            },
            'verifyPackLogEntry' => fn(array $a) => ActionsTransparency::verifyPackLogEntry($a[0],
                ['statement' => Base::bytes($a[1]->get('statement')), 'receipt' => Base::bytes($a[1]->get('receipt'))],
                ['registry' => Pca::unb64u($a[2]->get('registry')), 'log' => Pca::unb64u($a[2]->get('log'))], $a[3]),
        ]);
    }
}
