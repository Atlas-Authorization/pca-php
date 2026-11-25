<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Prohibitions.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The prohibition names the shared vectors and the base corpus do not reach, against the TS reference: every case of
 * test-data/ref-prohibitions.json.gz (constants, validateWhen, whenMatches, signConstitution, the non-strict advanceState, evidenceDigest,
 * composeAuthority). A secret is {"$seed": label} = sha256("atlas-pca-conformance/" . label); any other key value is refused.
 */
final class RefProhibitionsDifferentialTest extends TestCase
{
    private const FILE = 'ref-prohibitions.json.gz';
    private const TOTAL = 1637;

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

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'constants' => static fn(array $a) => ['CONSTITUTION_VERSION' => Prohibitions::CONSTITUTION_VERSION, 'CONSTITUTION_SIG_DOMAIN' => Prohibitions::CONSTITUTION_SIG_DOMAIN,
                'EVIDENCE_VERSION' => Prohibitions::EVIDENCE_VERSION, 'SAFETY_EVIDENCE_SIG_DOMAIN' => Prohibitions::SAFETY_EVIDENCE_SIG_DOMAIN,
                'STATE_DIGEST_DOMAIN' => Prohibitions::STATE_DIGEST_DOMAIN, 'STATE_CHAIN_DOMAIN' => Prohibitions::STATE_CHAIN_DOMAIN,
                'MAX_LEDGER' => Prohibitions::MAX_LEDGER, 'MAX_INVARIANTS' => Prohibitions::MAX_INVARIANTS, 'MAX_DEADLINE' => Prohibitions::MAX_DEADLINE],
            'validateWhen' => static fn(array $a) => Prohibitions::validateWhen($a[0], $a[1]),
            'whenMatches' => static fn(array $a) => Prohibitions::whenMatches($a[0], $a[1]),
            'signConstitution' => static fn(array $a) => Prohibitions::signConstitution($a[0], self::key($a[1])),
            'advanceState' => static fn(array $a) => count($a) > 3 ? Prohibitions::advance($a[0], $a[1], $a[2], $a[3]) : Prohibitions::advance($a[0], $a[1], $a[2]),
            'evidenceDigest' => static fn(array $a) => Prohibitions::evidenceDigest($a[0]),
            'composeAuthority' => static function (array $a) {
                $r = Prohibitions::composeAuthority($a[0], $a[1], $a[2], $a[3]);
                $p = $r['prohibition'];
                return ['allow' => $r['allow'], 'decidedBy' => $r['decidedBy'], 'permitted' => $r['permitted'],
                    'prohibition' => ['ok' => $p['ok'], 'violated' => $p['violated'], 'reasons' => $p['reasons'], 'evaluated' => $p['evaluated']]];
            },
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
