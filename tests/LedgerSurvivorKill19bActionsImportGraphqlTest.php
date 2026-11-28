<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\ActionsImportGraphql;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsImportGraphql.php';

/** mutation kills for src/ActionsImportGraphql.php, second pass: the documented token cap default and a string ending in a lone backslash. */
final class LedgerSurvivorKill19bActionsImportGraphqlTest extends TestCase
{
    /** The default token cap is two million, and parseGraphqlSdl uses it when no cap is passed. */
    public function testDefaultTokenCap(): void
    {
        $this->assertSame(2000000, ActionsImportGraphql::DEFAULT_MAX_TOKENS);
        $p = (new \ReflectionMethod(ActionsImportGraphql::class, 'parseGraphqlSdl'))->getParameters()[1];
        $this->assertSame(2000000, $p->getDefaultValue());
    }

    /** A backslash as the last byte of a one-character string leaves it unterminated; it must not step back onto the opening quote. */
    public function testTrailingBackslashAfterOneCharacter(): void
    {
        try {
            ActionsImportGraphql::parseGraphqlSdl('type T { "x\\');
            $msg = 'ok';
        } catch (ActionKitError $e) {
            $msg = $e->codeName . ': ' . $e->getMessage();
        }
        $this->assertSame('bad_source: unterminated GraphQL string', $msg);
    }
}
