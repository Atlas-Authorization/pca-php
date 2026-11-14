<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\Approval;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The canonical approval render (K7) against the TS reference: test-data/k05-approval.json.gz (k05-oracles/approval-oracle.mts). */
final class K05ApprovalDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-approval.json.gz';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    /** A JSON integer argument (-0 = 0) for the typed (int, int) port, else null (the reference refuses every such case). */
    private static function int(mixed $v): ?int
    {
        return $v instanceof Num && $v->isInt() ? $v->int() : null;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'approvalRenderShapeError' => fn(array $a) => Approval::renderShapeError($a[0]),
            'approvalRenderDigest' => fn(array $a) => Approval::renderDigest($a[0]),
            'approvalChallengeB64u' => fn(array $a) => Approval::challenge($a[0], $a[1]),
            'bindingWords' => fn(array $a) => Approval::bindingWords($a[0]),
            'renderApproval' => fn(array $a) => Approval::render($a[0], $a[1], false),
            'validateDef' => fn(array $a) => Actions::validateDef($a[0]),
            'psd2Linking' => fn(array $a) => Approval::psd2Linking($a[0]),
            'minorToDecimal' => function (array $a) {
                [$m, $e] = [self::int($a[0]), self::int($a[1])];
                return $m === null || $e === null ? [K05::SKIP, 'typed (int, int) port: a non-integer argument cannot be passed'] : Approval::minorToDecimal($m, $e);
            },
            'approvalBatch' => function (array $a, Obj $c) {
                $r = Approval::batch($a[0]);
                $w = $c->get('out');
                if ($w instanceof Obj && $w->get('challenge') instanceof Obj) {
                    $r->set('challenge', Obj::of(['$bytes' => $r->get('challenge')])); // the reference returns the challenge as bytes
                }
                return $r;
            },
            'spcExpectation' => fn() => [K05::SKIP, 'not in the PHP port (SPC expectation is TS-only)'],
            'cibaApprovalDetails' => fn() => [K05::SKIP, 'not in the PHP port (CIBA details are TS-only)'],
        ]);
    }
}
