<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Contracts.php';
require_once __DIR__ . '/../src/Prohibitions.php';

use Atlas\Pca\Contracts;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Behavioural contracts against the TS reference: every case of test-data/ref-contracts.json.gz (constants, validateClause, contractId,
 * signContract, embeddedConstitution, contractFromConstitution, checkContract, advanceContract, checkAndAdvanceContract).
 * A secret is {"$seed": label} = sha256("atlas-pca-conformance/" . label); any other key value is refused. The nesting depth is a PHP int:
 * a fractional depth is rounded up, which reaches the nesting bound at the same level as the reference's `depth > 16`.
 */
final class RefContractsDifferentialTest extends TestCase
{
    private const FILE = 'ref-contracts.json.gz';
    private const TOTAL = 1269;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function key(mixed $v): KeyPair
    {
        if (!($v instanceof Obj) || $v->keys() !== ['$seed'] || !is_string($v->get('$seed'))) {
            throw new \InvalidArgumentException('not a private key');
        }
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $v->get('$seed'), true));
    }

    /** The options object as the assoc array the native takes; JSON null stays null (the reference refuses it). */
    private static function opts(mixed $v): ?array
    {
        if (!($v instanceof Obj)) {
            return null;
        }
        $o = [];
        foreach ($v->keys() as $k) {
            $o[$k] = $v->get($k);
        }
        return $o;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['CONTRACT_VERSION' => Contracts::CONTRACT_VERSION, 'CONTRACT_SIG_DOMAIN' => Contracts::CONTRACT_SIG_DOMAIN,
                'MAX_CLAUSES' => Contracts::MAX_CLAUSES, 'MAX_CLAUSE_DEPTH' => Contracts::MAX_CLAUSE_DEPTH],
            'validateClause' => static function (array $a) {
                $seen = [];
                foreach ($a[1] as $id) {
                    $seen['k' . $id] = true;
                }
                return Contracts::validateClause($a[0], $seen, (int)ceil((float)Prohibitions::fin($a[2])));
            },
            'contractId' => static fn(array $a) => Contracts::contractId($a[0]),
            'signContract' => static fn(array $a) => Contracts::signContract($a[0], self::key($a[1])),
            'embeddedConstitution' => static fn(array $a) => Contracts::embeddedConstitution($a[0]),
            'contractFromConstitution' => static fn(array $a) => Contracts::contractFromConstitution($a[0]),
            'checkContract' => static fn(array $a) => Contracts::check($a[0], $a[1], $a[2]),
            'advanceContract' => static fn(array $a) => count($a) > 3 ? Contracts::advance($a[0], $a[1], $a[2], self::opts($a[3])) : Contracts::advance($a[0], $a[1], $a[2]),
            'checkAndAdvanceContract' => static fn(array $a) => count($a) > 4
                ? Contracts::checkAndAdvance($a[0], $a[1], $a[2], $a[3], self::opts($a[4]))
                : Contracts::checkAndAdvance($a[0], $a[1], $a[2], $a[3]),
        ]);
    }

    public function testCorpusHasTheExpectedCaseTotal(): void
    {
        $n = 0;
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            $n += str_starts_with($line, '{"fn"') ? 1 : 0;
        }
        $this->assertSame(self::TOTAL, $n);
    }
}
