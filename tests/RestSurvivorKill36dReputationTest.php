<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Reputation.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Reputation;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/Reputation.php: the record cap boundary, exposure sign, quote input checks, the caller's floor, quote shape and price checks. */
final class RestSurvivorKill36dReputationTest extends TestCase
{
    private static function underwriter(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/underwriter-36d', true));
    }

    private static function rep(float $score): Obj
    {
        return Obj::of(['subject' => 'agent-1', 'score' => $score]);
    }

    /** Exactly MAX_REPUTATION_RECORDS disputes is allowed; one more is too many. */
    public function testDisputeCapIsInclusive(): void
    {
        $d = Obj::of(['id' => 'd1', 'subject' => 's', 'slashed' => false, 'at' => 0]);
        $max = Reputation::MAX_REPUTATION_RECORDS;
        $this->assertNull(Reputation::validateReputationInput(Obj::of(['subject' => 's', 'disputes' => array_fill(0, $max, $d)])));
        $this->assertSame('too many records', Reputation::validateReputationInput(Obj::of(['subject' => 's', 'disputes' => array_fill(0, $max + 1, $d)])));
    }

    /** A negative-zero exposure prices as +0 coverage, never -0. */
    public function testNegativeZeroExposureIsPositiveZero(): void
    {
        $p = Reputation::priceCoverage(self::rep(1.0), -0.0);
        $this->assertFalse($p['declined']);
        $this->assertSame(INF, fdiv(1.0, $p['coverage']));
        $this->assertSame(INF, fdiv(1.0, $p['premium']));
    }

    /** A non-finite `now` is refused even with a valid ttl. */
    public function testNonFiniteNowIsRefused(): void
    {
        try {
            Reputation::issueCoverageQuote(self::rep(1.0), 100, self::underwriter(), NAN, 1000);
            $this->fail('no InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('issueCoverageQuote: now and ttlMs must be finite, ttlMs > 0', $e->getMessage());
        }
    }

    /** The caller's underwriting floor is the one priced: a score under it is declined. */
    public function testCallerMinScoreIsUsed(): void
    {
        $q = Reputation::issueCoverageQuote(self::rep(0.4), 100, self::underwriter(), 1000, 1000, ['minScore' => 0.5]);
        $this->assertTrue($q->get('declined'));
        $this->assertFalse(Reputation::issueCoverageQuote(self::rep(0.4), 100, self::underwriter(), 1000, 1000)->get('declined'));
    }

    /** Only an Obj is a quote: an object that merely answers get/without like a valid quote is malformed. */
    public function testQuoteMustBeAnObj(): void
    {
        $kp = self::underwriter();
        $q = Reputation::issueCoverageQuote(self::rep(1.0), 100, $kp, 1000, 1000);
        $this->assertSame(['ok' => true], Reputation::verifyCoverageQuote($q, $kp->public, 1500));
        $fake = new class ($q) {
            public function __construct(private Obj $o)
            {
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function without(string ...$drop): Obj
            {
                return $this->o->without(...$drop);
            }
        };
        $this->assertSame(['ok' => false, 'reason' => 'malformed'], Reputation::verifyCoverageQuote($fake, $kp->public, 1500));
    }

    /** A signed quote whose declined flag alone disagrees with the stated inputs is a price mismatch. */
    public function testDeclinedFlagAloneIsAPriceMismatch(): void
    {
        $kp = self::underwriter();
        $claim = Reputation::issueCoverageQuote(self::rep(1.0), 100, $kp, 1000, 1000)->without('sig');
        $claim->set('declined', true);
        $claim->set('sig', Pca::b64u($kp->sign(Reputation::COVERAGE_QUOTE_DOMAIN . Json::canonicalizeLenient($claim))));
        $this->assertSame(['ok' => false, 'reason' => 'price-mismatch'], Reputation::verifyCoverageQuote($claim, $kp->public, 1500));
    }

    /** Records that are not a list are refused, not read as no records. */
    public function testNonListRecordsAreRefused(): void
    {
        try {
            Reputation::disputesFromSettlements('x', 'pk', static fn(string $id): ?string => null);
            $this->fail('no InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('disputesFromSettlements: records is not a list', $e->getMessage());
        }
    }
}
