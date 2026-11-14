<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Obj;
use Atlas\Pca\PackTracker;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The action-kit registry layer against the TS reference: test-data/k05-actionregistry.json.gz (k05-oracles/actionregistry-oracle.mts):
 * evolution records, registry signatures, re-approvals, the grant pin, signed packs + shards, the rollback tracker, rule 22, pack proofs.
 */
final class K05ActionsRegistryDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-actionregistry.json.gz';
    private const TYPED = 'typed PHP signature: the argument cannot be passed';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    /** The generator's ALLKEYS (Ed25519, ML-DSA-65, hybrid): the keys argument of its `verifyRegistrySig/ml ok` case. */
    private static function allKeys(): mixed
    {
        static $keys = null;
        if ($keys === null) {
            foreach (K05::cases(self::FILE, 'verifyRegistrySig', 0) as $c) {
                if ($c->get('name') === 'verifyRegistrySig/ml ok') {
                    $keys = $c->get('args')[3];
                }
            }
        }
        return $keys;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'compareVersions' => fn(array $a) => is_string($a[0]) && is_string($a[1]) ? ActionsRegistry::compareVersions($a[0], $a[1]) <=> 0 : [K05::SKIP, self::TYPED],
            'packDefs' => fn(array $a) => $a[0] instanceof Obj
                ? array_map(static fn(Obj $d) => $d->get('verb'), ActionsRegistry::packDefs($a[0], $a[1])) : [K05::SKIP, self::TYPED],
            'evolutionRecordError' => fn(array $a) => ActionsRegistry::evolutionRecordError($a[0], $a[1] === true),
            'evolutionDiffDigest' => fn(array $a) => ActionsRegistry::evolutionDiffDigest($a[0]),
            'verifyRegistrySig' => function (array $a) {
                if (!is_string($a[0]) || !($a[1] instanceof Obj)) {
                    return [K05::SKIP, self::TYPED];
                }
                $r = IntentV2::verifyRegistrySig($a[0], $a[1], $a[2], $a[3]);
                return $r['ok'] ? null : $r['reason'];
            },
            'verifyEvolutionRecord' => function (array $a) {
                $r = ActionsRegistry::verifyEvolutionRecord($a[0], $a[1]);
                return $r['ok'] ? null : $r['reason'];
            },
            'reapprovalValid' => fn(array $a) => ActionsRegistry::reapprovalValid($a[0], $a[1], $a[2], $a[3], $a[4]),
            'actionPinError' => fn(array $a) => ActionsRegistry::actionPinError($a[0]),
            'decidePin' => function (array $a) {
                $i = [];
                foreach ($a[0]->keys() as $key) {
                    $i[$key] = $a[0]->get($key);
                }
                return ActionsRegistry::decidePin($i);
            },
            'packShapeError' => fn(array $a) => ActionsRegistry::packShapeError($a[0], $a[1] === true),
            'verifyPack' => function (array $a) {
                $r = ActionsRegistry::verifyPack($a[0], $a[1], $a[2]);
                return $r['ok'] ? ['ok' => true, 'digest' => $r['digest'], 'verbs' => array_map(static fn(Obj $d) => $d->get('verb'), $r['defs'])] : $r;
            },
            'packTracker' => function (array $a, Obj $c) {
                // comparison: ok / status / code, the reason only for bad_pack (natives do not recompute the semantic upgrade diff)
                $c->set('out', array_map(static fn($o) => $o instanceof Obj && $o->get('code') !== 'bad_pack' ? $o->without('reason') : $o, $c->get('out')));
                $t = new PackTracker(self::allKeys());
                return array_map(static function (array $step) use ($t) {
                    $r = $t->accept($step[0], $step[1] ?? null);
                    if (($r['code'] ?? 'bad_pack') !== 'bad_pack') {
                        unset($r['reason']);
                    }
                    return $r;
                }, $a[0]);
            },
            'rule22Decide' => fn(array $a) => !(is_string($a[1]) && $a[2] instanceof Obj && is_array($a[3]) && array_is_list($a[3])) ? [K05::SKIP, self::TYPED]
                : ActionsRegistry::rule22Decide($a[0], $a[1], $a[2], $a[3]),
            'verifyPackProof' => fn(array $a) => is_string($a[0]) && is_string($a[2])
                ? Actions::verifyPackProof($a[0], $a[1], $a[2]) : [K05::SKIP, self::TYPED],
        ]);
    }
}
