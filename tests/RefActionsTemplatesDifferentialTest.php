<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsTemplates;
use Atlas\Pca\Obj;
use Atlas\Pca\StarterTemplate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsTemplates.php';

/** The starter templates (custom traits and authoring YAML under several namespaces) against the TS reference: test-data/ref-actions-templates-py.json.gz. */
final class RefActionsTemplatesDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-templates-py.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function meta(?StarterTemplate $t): ?Obj
    {
        return $t === null ? null : Obj::of(['id' => $t->id, 'title' => $t->title, 'description' => $t->description, 'ns' => $t->ns]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'templateList' => fn(array $a) => array_map([self::class, 'meta'], ActionsTemplates::starterTemplates()),
            'starterTemplate' => fn(array $a) => self::meta(ActionsTemplates::starterTemplate($a[0])),
            'templateTraits' => fn(array $a) => ActionsTemplates::starterTemplate($a[0])->traits($a[1]),
            'templateYaml' => fn(array $a) => ActionsTemplates::starterTemplate($a[0])->yaml($a[1]),
        ]);
    }
}
