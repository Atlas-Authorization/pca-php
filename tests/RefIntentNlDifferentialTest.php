<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Sign;
use Atlas\Pca\Catalog;
use Atlas\Pca\IntentCompilers;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The natural-language facade compiler against the TS reference: test-data/ref-intent-nl-java.json.gz (grounding prompt, strict parse, compiler). */
final class RefIntentNlDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-nl-java.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    /** The built-in catalog plus extra connector specs (null: the built-in one, i.e. no catalog argument). */
    private static function cat(mixed $extras): ?array
    {
        if ($extras === null) {
            return null;
        }
        $out = Catalog::BUILTIN_ACTIONS;
        foreach ($extras as $e) {
            $a = Sign::plain($e);
            $a['verb'] = $a['connector'] . '.' . $a['action'];
            $out[] = $a;
        }
        return $out;
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'nlPrompt' => static fn(array $a) => IntentCompilers::nlPrompt($a[0], self::cat($a[1])),
            'parseNLPolicy' => static fn(array $a) => IntentCompilers::parseNlPolicy($a[0], self::cat($a[1])),
            'nlRun' => static function (array $a) {
                [$text, $model, $extras] = $a;
                $comp = IntentCompilers::nlFacadeCompiler('nl', 'fam', static function (string $p) use ($model): string {
                    if ($model === 'THROWS') {
                        throw new \RuntimeException('llm down');
                    }
                    return $model;
                });
                return IntentCompilers::runCompilers(['text' => $text, 'catalog' => self::cat($extras)], [$comp]);
            },
            'nlCompile' => static function (array $a) {
                [$text, $model, $extras] = $a;
                $seen = [];
                $comp = IntentCompilers::nlFacadeCompiler('nl', 'fam', static function (string $p) use (&$seen, $model): string {
                    $seen[] = $p;
                    if ($model === 'THROWS') {
                        throw new \RuntimeException('llm down');
                    }
                    return $model;
                });
                $out = ($comp->compile)(['text' => $text, 'catalog' => self::cat($extras)]);
                return ['prompt' => $seen[0], 'output' => $out];
            },
        ]);
    }
}
