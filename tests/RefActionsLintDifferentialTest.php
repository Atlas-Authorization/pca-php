<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsLint;
use Atlas\Pca\ActionsUndoEngine;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsLint.php';

/** The lint rules, text and SARIF output and the definition-level undo structure against the TS reference: test-data/ref-actions-lint.json.gz. */
final class RefActionsLintDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-lint.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'lintDefs' => function (array $a) {
                $o = $a[1] ?? null;
                $has = $o instanceof Obj && $o->has('att');
                $att = $has ? $o->get('att') : null;
                return ActionsLint::lintDefs($a[0], $o instanceof Obj ? $o->without('att') : null, $has ? static fn() => $att : null);
            },
            'lintRulesDigest' => fn(array $a) => ActionsLint::lintRulesDigest(),
            'LINT_RULES' => fn(array $a) => ActionsLint::LINT_RULES,
            'lintText' => fn(array $a) => ActionsLint::lintText($a[0]),
            'toSarif' => fn(array $a) => ActionsLint::toSarif($a[0], $a[1] ?? null),
            'lintFails' => fn(array $a) => ActionsLint::lintFails($a[0], $a[1] ?? false),
            'mayBeReversible' => fn(array $a) => ActionsUndoEngine::mayBeReversible($a[0]),
            'reversibilityFor' => fn(array $a) => ActionsUndoEngine::reversibilityFor($a[0], $a[1]),
            'compensationShape' => fn(array $a) => ActionsUndoEngine::compensationShape($a[0], $a[1]),
        ]);
    }
}
