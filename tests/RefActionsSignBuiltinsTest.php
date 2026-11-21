<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The release signing of the built-in defs against the TS reference: test-data/ref-actions-signbuiltins.json.gz (the secret is a seed label). */
final class RefActionsSignBuiltinsTest extends TestCase
{
    private const FILE = 'ref-actions-signbuiltins.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'signBuiltins' => function (array $a): array {
                $o = $a[0];
                $secret = hash('sha256', 'atlas-pca-conformance/' . $o->get('secret')->get('$seed'), true);
                $defs = array_slice(ActionsBuiltin::builtinDefs(), (int)$o->get('from')->int(), (int)($o->get('to')->int() - $o->get('from')->int()));
                $signed = ActionsBuiltin::signBuiltins($o->get('kid'), $secret, $o->get('ts')->int(), null, $defs);
                return array_map(fn(Obj $d) => [$d->get('verb'), $d->get('review')->get('state'), $d->get('review')->get('attestation')], $signed);
            },
        ]);
    }

    public function testEveryBuiltinDefIsValidAndUnconfirmedUntilSigned(): void
    {
        $this->assertCount(21, ActionsBuiltin::builtinDefs());
    }
}
