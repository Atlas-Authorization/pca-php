<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsImportGraphql;
use Atlas\Pca\ActionsImportGrpc;
use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsImportGraphql.php';
require_once __DIR__ . '/../src/ActionsImportGrpc.php';

/** The GraphQL and gRPC importers, SDL / introspection / .proto / descriptor-set parsers included, against the TS reference: test-data/ref-actions-import-sdl.json.gz. */
final class RefActionsImportSdlDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-import-sdl.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** The reference keeps types in a Map: its entries are compared as [key, value] pairs. */
    private static function gschema(Obj $s): Obj
    {
        $types = [];
        foreach ($s->get('types')->keys() as $k) {
            $types[] = [$k, $s->get('types')->get($k)];
        }
        $o = Obj::of(['types' => $types]);
        foreach (['query', 'mutation', 'subscription'] as $k) {
            if ($s->has($k)) {
                $o->set($k, $s->get($k));
            }
        }
        return $o;
    }

    /** @param array{messages:Obj,enums:Obj,services:list<mixed>} $m */
    private static function pmodel(array $m): Obj
    {
        $messages = [];
        foreach ($m['messages']->keys() as $k) {
            $messages[] = [$k, $m['messages']->get($k)];
        }
        $enums = [];
        foreach ($m['enums']->keys() as $k) {
            $enums[] = [$k, $m['enums']->get($k)['values']];
        }
        return Obj::of(['messages' => $messages, 'enums' => $enums, 'services' => $m['services']]);
    }

    private static function isBytes(mixed $v): bool
    {
        return $v instanceof Obj && $v->keys() === ['$bytes'];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'importGraphql' => fn(array $a) => ActionsImportGraphql::importGraphql($a[0], $a[1]),
            'parseGraphqlSdl' => fn(array $a) => self::gschema(ActionsImportGraphql::parseGraphqlSdl($a[0])),
            'fromIntrospection' => fn(array $a) => self::gschema(ActionsImportGraphql::fromIntrospection($a[0])),
            'importGrpc' => fn(array $a) => ActionsImportGrpc::importGrpc(self::isBytes($a[0]) ? new Bytes(Base::bytes($a[0])) : $a[0], $a[1]),
            'parseProto' => fn(array $a) => self::pmodel(ActionsImportGrpc::parseProto($a[0])),
            'parseDescriptorSet' => fn(array $a) => self::pmodel(ActionsImportGrpc::parseDescriptorSet(Base::bytes($a[0]))),
        ]);
    }
}
