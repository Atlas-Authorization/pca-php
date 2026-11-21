<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentRender;
use Atlas\Pca\IntentWitnesses;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Deterministic rendering and the back-translation diff against the TS reference: test-data/ref-intent-render.json.gz (conditions,
 * caveats, grants, questions, actions, claim IR and diffs). The boundary witnesses of the same corpus replay on IntentWitnesses.
 */
final class RefIntentRenderDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-render.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        $p = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'labelOf' => static fn(array $a) => IntentRender::labelOf($a[0]),
            'renderCondition' => static fn(array $a) => IntentRender::renderCondition($p($a[0])),
            'renderCaveat' => static fn(array $a) => IntentRender::renderCaveat($p($a[0])),
            'renderGrant' => static fn(array $a) => IntentRender::renderGrant($p($a[0])),
            'renderQuestion' => static fn(array $a) => IntentRender::renderQuestion($p($a[0]), $p($a[1])),
            'renderAction' => static fn(array $a) => IntentRender::renderAction($p($a[0]), $p($a[1])),
            'claimsOf' => static fn(array $a) => IntentRender::claimsOf($p($a[0]), $p($a[1])),
            'backTranslationDiff' => static fn(array $a) => IntentRender::backTranslationDiff($p($a[0]), $p($a[1]), $p($a[2])),
            'claimDiff' => static fn(array $a) => count($a) > 3 ? IntentRender::claimDiff($p($a[0]), $p($a[1]), $p($a[2]), $a[3]) : IntentRender::claimDiff($p($a[0]), $p($a[1]), $p($a[2])),
            'boundaryWitnesses' => static fn(array $a) => IntentWitnesses::boundaryWitnesses($p($a[0]), $p($a[1])),
            'checkWitnesses' => static function (array $a) use ($p) {
                $mode = $a[1];
                $oracle = static function ($w) use ($mode) {
                    $allows = $w->get('grantAllows');
                    return match ($mode) {
                        'agree' => $allows,
                        'flip' => !$allows,
                        'flip-boundary' => $w->get('kind') === 'boundary' ? !$allows : $allows,
                        default => $w->get('side') === 'inside' && $w->get('kind') !== 'unconstrained',
                    };
                };
                return IntentWitnesses::checkWitnesses($p($a[0]), $oracle);
            },
        ]);
    }
}
