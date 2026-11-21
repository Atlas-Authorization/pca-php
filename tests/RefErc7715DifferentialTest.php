<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Erc7715;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The ERC-7715 mapping against the TS reference: test-data/ref-erc7715.json.gz (chainId crosses as a decimal string). */
final class RefErc7715DifferentialTest extends TestCase
{
    private const FILE = 'ref-erc7715.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function verify(array $a): ?string
    {
        $x = $a[3];
        $o = ['allowedManagers' => $x instanceof Obj ? $x->get('allowedManagers') : null];
        $owners = $x instanceof Obj ? $x->get('owners') : null;
        if ($owners instanceof Obj) {
            $o['contextOwner'] = static fn(string $c): mixed => $owners->get($c);
        }
        return Erc7715::verifyGrantedPermission($a[0], $a[1], $a[2], $o);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'grantToPermissionRequest' => fn(array $a) => Erc7715::grantToPermissionRequest($a[0], $a[1]),
            'supportsRequest' => fn(array $a) => Erc7715::supportsRequest($a[0], $a[1]),
            // the one zero-argument case is revokeParams(undefined): its member is dropped
            'revokeParams' => fn(array $a) => $a === [] ? new Obj() : Erc7715::revokeParams($a[0]),
            'verifyGrantedPermission' => fn(array $a) => self::verify($a),
            'grantDigestOf' => fn(array $a) => Erc7715::grantDigestOf($a[0]),
        ]);
    }
}
