<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Oauth;
use Atlas\Pca\Receipts;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/Oauth.php';
require_once __DIR__ . '/../src/Receipts.php';

/** The receipt log and the discovery parsers against the TS reference: test-data/ref-core-parity-pure.json.gz (the other functions of the file are replayed elsewhere). */
final class RefCoreParityPureDifferentialTest extends TestCase
{
    private const FILE = 'ref-core-parity-pure.json.gz';
    private const FNS = ['receiptFor', 'appendReceipt', 'verifyReceiptChain', 'receiptHead', 'parseDiscoveryDocument', 'parseDiscoveryIntent', 'acceptsSuite'];

    public static function provide(): array
    {
        return array_filter(Base::datasets(self::FILE), static fn(array $d): bool => in_array($d[1], self::FNS, true));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $at = static fn(mixed $v): ?int => $v === null ? null : $v->int();
        Base::run($file, $fn, $k, [
            'receiptFor' => fn(array $a) => Receipts::receiptFor($a[0], $a[1]->int(), $a[2], $a[3], $at($a[4])),
            'appendReceipt' => fn(array $a) => Receipts::appendReceipt($a[0], $a[1], $a[2], $at($a[3])),
            'verifyReceiptChain' => fn(array $a) => Receipts::verifyReceiptChain($a[0]),
            'receiptHead' => fn(array $a) => Receipts::receiptHead($a[0]),
            'parseDiscoveryDocument' => fn(array $a) => Oauth::parseDiscoveryDocument($a[0]),
            'parseDiscoveryIntent' => fn(array $a) => Oauth::parseDiscoveryIntent($a[0]),
            'acceptsSuite' => fn(array $a) => Oauth::acceptsSuite($a[0], $a[1]),
        ]);
    }
}
