<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentWitnesses;
use Atlas\Pca\Js;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Boundary witnesses and their check against the TS reference: the witness functions of test-data/ref-intent-render.json.gz (the rendering functions belong to the render module). */
final class RefIntentWitnessesDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-render.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $skip = static fn() => [Base::SKIP, 'render module'];
        Base::run($file, $fn, $k, [
            'boundaryWitnesses' => fn(array $a) => IntentWitnesses::boundaryWitnesses($a[0], $a[1]),
            'checkWitnesses' => function (array $a) {
                $mode = $a[1];
                $oracle = static fn($w): bool => match ($mode) {
                    'agree' => Js::opt($w, 'grantAllows') === true,
                    'flip' => Js::opt($w, 'grantAllows') !== true,
                    'flip-boundary' => Js::opt($w, 'kind') === 'boundary' ? Js::opt($w, 'grantAllows') !== true : Js::opt($w, 'grantAllows') === true,
                    default => Js::opt($w, 'side') === 'inside' && Js::opt($w, 'kind') !== 'unconstrained',
                };
                return IntentWitnesses::checkWitnesses($a[0], $oracle);
            },
            'labelOf' => $skip, 'renderCondition' => $skip, 'renderCaveat' => $skip, 'renderGrant' => $skip, 'renderQuestion' => $skip,
            'renderAction' => $skip, 'claimsOf' => $skip, 'backTranslationDiff' => $skip, 'claimDiff' => $skip,
        ]);
    }
}
