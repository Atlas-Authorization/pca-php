<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Connectors.php';
require_once __DIR__ . '/../src/ConnectorsProviders.php';

use Atlas\Pca\Connectors;
use Atlas\Pca\ConnectorsProviders;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The seeded connector provider catalog against the TS reference: every case of test-data/ref-connectors-providers.json.gz (each provider
 * manifest with its digest and validity, the structural invariants every built-in holds, the built-in order and catalog digest, and
 * ids outside the catalog).
 */
final class RefConnectorsProvidersDifferentialTest extends TestCase
{
    private const FILE = 'ref-connectors-providers.json.gz';
    private const FNS = ['provider' => 15, 'invariants' => 15, 'builtinManifests' => 1, 'unknownProvider' => 9];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function manifest(string $id): Obj
    {
        foreach (ConnectorsProviders::manifests() as $m) {
            if ($m->get('id') === $id) {
                return $m;
            }
        }
        throw new \OutOfBoundsException("no provider $id");
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'provider' => static function (array $a) {
                $m = self::manifest($a[0]);
                return Obj::of(['manifest' => $m, 'digest' => Connectors::manifestDigest($m), 'valid' => Connectors::validateManifest($m)['ok']]);
            },
            'invariants' => static function (array $a) {
                $m = self::manifest($a[0]);
                $scopes = $m->get('scopesAvailable');
                $default = $m->get('defaultScopes');
                return Obj::of(['defaultScopesSubset' => array_diff($default, $scopes) === [], 'scopesUnique' => count(array_unique($scopes)) === count($scopes),
                    'idMatchesKey' => $m->get('id') === $a[0],
                    'httpsEndpoints' => str_starts_with($m->get('authorizeUrl'), 'https://') && str_starts_with($m->get('tokenUrl'), 'https://')]);
            },
            'builtinManifests' => static function (array $a) {
                $ms = ConnectorsProviders::manifests();
                return Obj::of(['ids' => array_map(static fn(Obj $m) => $m->get('id'), $ms), 'digests' => array_map(static fn(Obj $m) => Connectors::manifestDigest($m), $ms),
                    'catalogDigest' => Connectors::catalogDigest()]);
            },
            'unknownProvider' => static fn(array $a) => Obj::of(['found' => Connectors::getProvider($a[0]) !== null]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
