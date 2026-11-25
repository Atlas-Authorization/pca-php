<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentCompilers;
use Atlas\Pca\IntentCompiler;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The k-compiler pipeline against the TS reference: test-data/ref-intent-compilers.json.gz (slot prompt and strict slot parsing, compiler
 * panels with failing members, structural disagreement, committee anchors, panel flags, compile-and-compare). Compiler specs:
 * captured / fixed / throws / slots / slotsThrows. Doubles are compared to 1e-12 relative.
 */
final class RefIntentCompilersDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-compilers.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function compiler(Obj $s): IntentCompiler
    {
        $id = (string)$s->get('id');
        $fam = (string)$s->get('family');
        return match ($s->get('kind')) {
            'captured' => $s->has('id') ? IntentCompilers::capturedSlotsCompiler($id) : IntentCompilers::capturedSlotsCompiler(),
            'fixed' => IntentCompilers::fixedCompiler($id, $fam, static fn() => $s->get('policy')),
            'throws' => IntentCompilers::fixedCompiler($id, $fam, static function () { throw new \RuntimeException('boom'); }),
            'slots' => IntentCompilers::slotsCompiler($id, $fam, static fn() => $s->get('raw')),
            default => IntentCompilers::slotsCompiler($id, $fam, static function () { throw new \RuntimeException('llm down'); }),
        };
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        $p = static fn($x) => WalletOmega::plain($x);
        $close = static fn($have, Obj $c) => RefWalletDifferentialTest::close($have, $c);
        $specs = static fn($list) => array_map(self::compiler(...), $p($list));
        Base::run($file, $fn, $k, [
            'slotsPrompt' => static fn(array $a) => IntentCompilers::slotsPrompt($a[0]),
            'parseSlotsJSON' => static fn(array $a) => IntentCompilers::parseSlotsJson($a[0]),
            'runScenario' => static fn(array $a, Obj $c) => $close(IntentCompilers::runCompilers($p($a[0]), $specs($a[1])), $c),
            'analyze' => static fn(array $a, Obj $c) => $close(IntentCompilers::analyzeDisagreement($p($a[0]), $p($a[1])), $c),
            'flags' => static fn(array $a) => IntentCompilers::panelFlags(IntentCompilers::analyzeDisagreement($p($a[0]), $p($a[1]))),
            'anchors' => static fn(array $a) => IntentCompilers::committeeAnchors($p($a[0]), $p($a[1])),
            'compareScenario' => static fn(array $a, Obj $c) => $close(IntentCompilers::compileAndCompare($p($a[0]), $specs($a[1]), $p($a[2])), $c),
        ]);
    }
}
