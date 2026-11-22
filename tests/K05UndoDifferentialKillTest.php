<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\Undo;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Undo windows (pure layer) against the TS reference: test-data/k05-undo.json.gz (k05-oracles/undo-oracle.mts). */
final class K05UndoDifferentialKillTest extends TestCase
{
    private const FILE = 'k05-undo.json.gz';

    public static function provide(): array
    {
        return K05::datasets(self::FILE);
    }

    private static function key(mixed $sk): KeyPair
    {
        return new KeyPair(Pca::unb64u($sk) ?? throw new \InvalidArgumentException('seed'));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        K05::run($file, $fn, $k, [
            'compensationDigest' => fn(array $a) => Undo::compensationDigest($a[0]),
            // the PHP API takes a KeyPair, which cannot hold a seed that is not 32 bytes (the reference's signer_missing)
            'signUndoToken' => fn(array $a) => strlen((string)Pca::unb64u((string)$a[1])) !== 32
                ? [K05::SKIP, 'typed PHP signature: a KeyPair cannot hold a seed that is not 32 bytes (signer_missing)']
                : Undo::signToken($a[0], self::key($a[1])),
            'undoTokenCheck' => fn(array $a) => Undo::tokenCheck($a[0], $a[1], $a[2], $a[3]),
            'encodeUndoToken' => fn(array $a) => Undo::encodeToken($a[0]),
            'undoTokenDigest' => fn(array $a) => Undo::tokenDigest($a[0]),
            'decodeUndoToken' => fn(array $a) => Undo::decodeToken($a[0]),
            'signUndoReceipt' => fn(array $a) => Undo::signReceipt($a[0], self::key($a[1])),
            'undoReceiptDigest' => fn(array $a) => Undo::receiptDigest($a[0]),
            'verifyUndoReceipt' => fn(array $a) => Undo::verifyReceipt($a[0], $a[1]),
            'undoReceiptChainError' => fn(array $a) => Undo::receiptChainError($a[0], $a[1]),
            'undoTransition' => fn(array $a) => Undo::transition($a[0], $a[1], $a[2]),
            'resolveUndoWindow' => fn(array $a) => Undo::resolveWindow($a[0], $a[1]),
        ]);
    }
}
