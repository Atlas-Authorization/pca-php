<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsRules;
use Atlas\Pca\Approvals;
use Atlas\Pca\MpcEc;
use Atlas\Pca\Notary;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Malformed input is refused (or read) the way the reference does, with no PHP warning (the suite fails on a warning). */
final class MalformedInputRefusalTest extends TestCase
{
    private static function rules(array $addresses, array $domains): Obj
    {
        return Obj::of(['recipients' => Obj::of(['param' => 'to', 'role' => 'x', 'addresses' => $addresses, 'domains' => $domains])]);
    }

    public function testAnAddressWithoutAnAtSignIsCoveredOnlyByTheDomainTheReferenceReadsFromIt(): void
    {
        // the reference reads `x.split('@')[1]` of "bob" as undefined, so the domain "undefined" covers it
        $r = ActionsRules::diffBusinessRules(new Obj(), self::rules(['bob'], []), self::rules([], ['undefined']));
        $this->assertSame(['rules.recipients: widen'], $r['reasons']);
        $r = ActionsRules::diffBusinessRules(new Obj(), self::rules(['bob'], []), self::rules([], ['other']));
        $this->assertSame(['rules.recipients: incomparable'], $r['reasons']);
    }

    public function testALineageWithoutAChainIsAnEngineTypeError(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Cannot read properties of undefined (reading 'map')");
        Approvals::describeGoalLineage([]);
    }

    public function testALineageWhoseChainIsNotAListIsATypeError(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('lineage.chain.map is not a function');
        Approvals::describeGoalLineage(['chain' => 'x']);
    }

    public function testAWitnessWithoutLeavesIsAnEngineTypeError(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Cannot read properties of undefined (reading 'findIndex')");
        Notary::discloseField(new Obj(), new Obj(), 'a');
    }

    public function testLittleEndianBytesOfAZeroLengthKeepTheWholeValueLikeTheReference(): void
    {
        $this->assertSame('', MpcEc::le(gmp_init(0), 0));
        $this->assertSame("\x34\x12", MpcEc::le(gmp_init(0x1234), 0));
        $this->assertSame("\x12", MpcEc::le(gmp_init(0x123), 0)); // an odd trailing digit is dropped, as Buffer.from(hex, 'hex') does
        $this->assertSame('', MpcEc::le(gmp_init(5), -1)); // a negative length cuts the front of the text away
        $this->assertSame("\x34\x12", MpcEc::le(gmp_init(0x1234), 2));
    }
}
