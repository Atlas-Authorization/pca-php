<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Evidence;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use PHPUnit\Framework\TestCase;

/**
 * Evidence bundle producer side: the closed-shape refusals, the normal-form / commitment refusals (thrown errors like the
 * reference's), and the accumulator cap reader, over the chargeback walkthrough of test-data/ref-evidence-bundle-py.json.gz.
 */
final class EvidenceSurvivorKill2Test extends TestCase
{
    private static ?string $line = null;

    /** A fresh copy of the walkthrough bundle (every call parses again, so a test may edit it freely). */
    private static function bundle(): Obj
    {
        if (self::$line === null) {
            $h = gzopen(__DIR__ . '/../test-data/ref-evidence-bundle-py.json.gz', 'rb');
            self::assertNotFalse($h);
            while (($l = gzgets($h)) !== false) {
                if (str_contains(substr($l, 0, 160), '"name":"verifyEvidenceBundle/walkthrough#0"')) {
                    self::$line = rtrim(rtrim($l, "\r\n"), ',');
                    break;
                }
            }
            gzclose($h);
            self::assertNotNull(self::$line, 'walkthrough case not found');
        }
        $c = (new Parser(self::$line, PHP_INT_MAX))->run();
        return $c->get('args')[0];
    }

    private static function j(string $json): mixed
    {
        return (new Parser($json, 64))->run();
    }

    public function testTheWalkthroughIsWellFormed(): void
    {
        $this->assertNull(Evidence::bundleShapeError(self::bundle()));
    }

    /** A malformed principal entry stays a refusal even when a well-formed one follows it. */
    public function testAnEarlierMalformedPrincipalIsNotWashedOutByALaterGoodOne(): void
    {
        $b = self::bundle();
        $b->get('session_root')->set('principals', self::j('[{}, {"key": "k"}]'));
        $this->assertSame('session_root.principals must be a non-empty key list', Evidence::bundleShapeError($b));
    }

    /** The optional W-B members, when present, must be arrays (facts is checked like the others). */
    public function testAPresentFactsMemberMustBeAnArray(): void
    {
        $b = self::bundle();
        $b->set('facts', new Obj());
        $this->assertSame('facts must be an array', Evidence::bundleShapeError($b));
    }

    /** A present event delta must be a NON-NEGATIVE integer: -1 is refused. */
    public function testANegativeEventDeltaIsRefused(): void
    {
        $b = self::bundle();
        $b->get('accumulator')->get('events')[0]->set('delta', self::j('-1'));
        $this->assertSame('accumulator.events[0].delta must be a non-negative integer', Evidence::bundleShapeError($b));
    }

    /** A present sequencer_keys member must be an array. */
    public function testAPresentSequencerKeysMemberMustBeAnArray(): void
    {
        $b = self::bundle();
        $b->get('accumulator')->set('sequencer_keys', 'x');
        $this->assertSame('accumulator.sequencer_keys must be an array', Evidence::bundleShapeError($b));
    }

    /** normalizeBundle of a non-object fails like the reference: reading members of null, `sort` of anything else. */
    public function testNormalizingANullBundleFailsReadingItsMaps(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Cannot read properties of null (reading 'maps')");
        Evidence::normalizeBundle(null);
    }

    public function testNormalizingAStringBundleFailsOnSort(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('sort is not a function');
        Evidence::normalizeBundle('x');
    }

    /** A delta grant whose caveats are not a list cannot be ordered (`find is not a function`). */
    public function testDeltasWithoutCaveatListsCannotBeOrdered(): void
    {
        $b = self::bundle();
        $b->set('deltas', [new Obj(), new Obj()]);
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('find is not a function');
        Evidence::normalizeBundle($b);
    }

    /** The commitment form refuses a bundle without a statement and an effect that is null (cannot destructure). */
    public function testTheCommitmentFormRefusesAMissingStatement(): void
    {
        $b = self::bundle()->without('statement');
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("cannot read 'commit' of undefined");
        Evidence::commitmentForm($b);
    }

    public function testTheCommitmentFormRefusesANullEffect(): void
    {
        $b = self::bundle();
        $b->set('effects', [null]);
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('cannot destructure');
        Evidence::commitmentForm($b);
    }

    /** A delta grant (the walkthrough's D_1) with its envelope predicates replaced. */
    private static function grantWith(string $predicates): Obj
    {
        $g = self::bundle()->get('deltas')[0];
        $g->get('caveats')[0]->set('predicates', self::j($predicates));
        return $g;
    }

    /** A leaf on another field is skipped, not the end of the `where` list; an integral cap comes back as an int. */
    public function testCapOfSkipsLeavesOnOtherFieldsAndReturnsAnInt(): void
    {
        $g = self::grantWith('[{"resource": "*", "verb": "air.book", "where": [{"field": "env.acc.other.post", "op": "lte", "value": 5}, {"field": "env.acc.a.post", "op": "lte", "value": 100}]}]');
        $this->assertSame(100, Evidence::capOf($g, 'a', 'air.book'));
        $this->assertNull(Evidence::capOf($g, 'a', 'air.cancel'));
    }

    /** A verb list is matched by String(verb), as the reference's `verbs.map(String)`. */
    public function testCapOfMatchesAVerbListByItsStringForm(): void
    {
        $g = self::grantWith('[{"resource": "*", "verb": [true], "where": [{"field": "env.acc.a.post", "op": "lte", "value": 7}]}]');
        $this->assertSame(7, Evidence::capOf($g, 'a', 'true'));
    }

    /** Across predicates (a union) the LOOSEST cap wins, whatever their order. */
    public function testCapOfTakesTheLoosestCapAcrossPredicates(): void
    {
        $g = self::grantWith('[{"resource": "*", "verb": "air.book", "where": [{"field": "env.acc.a.post", "op": "lte", "value": 100}]}, {"resource": "*", "verb": "air.book", "where": [{"field": "env.acc.a.post", "op": "lte", "value": 50}]}]');
        $this->assertSame(100, Evidence::capOf($g, 'a', 'air.book'));
    }

    /** At 9e15 (the int-conversion bound, exclusive) the cap stays a float. */
    public function testCapOfKeepsAFloatAtTheConversionBound(): void
    {
        $g = self::grantWith('[{"resource": "*", "verb": "air.book", "where": [{"field": "env.acc.a.post", "op": "lte", "value": 9000000000000000}]}]');
        $this->assertSame(9.0e15, Evidence::capOf($g, 'a', 'air.book'));
    }
}
