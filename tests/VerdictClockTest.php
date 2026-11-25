<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\VerifyVerdict;
use PHPUnit\Framework\TestCase;

/** The verdict's clock must be a finite number: anything else is refused before any check runs, with the reference's one reason. */
final class VerdictClockTest extends TestCase
{
    public function testAClockThatIsNotAFiniteNumberFailsClosedBeforeAnyCheck(): void
    {
        $grant = Obj::of(['id' => 'g', 'issuer' => 'i', 'holder' => 'h', 'caveats' => []]);
        foreach (['1', true, [], NAN, INF, -INF] as $now) {
            $v = VerifyVerdict::verify(Obj::of(['ver' => 2]), Obj::of(['grant' => $grant, 'now' => $now]));
            self::assertFalse($v['allow']);
            self::assertSame(['malformed' => 'fail'], $v['checks']);
            self::assertSame(['the verifier clock is not a finite time'], $v['reasons']);
        }
    }
}
