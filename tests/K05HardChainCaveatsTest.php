<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * A leaf whose `caveats` member is missing, null, {}, "x" or 5 is refused by the standalone chain verifier (TS allocationsMonotone: "malformed
 * caveats"). Here the hop is HAND-SIGNED with a valid signature, so only the type rules can refuse it; the well-typedness check
 * (`hop 0: malformed capability`) is hit first, ahead of the budget_alloc rule, and a control with [] verifies.
 */
final class K05HardChainCaveatsTest extends TestCase
{
    private static function root(KeyPair $kp, bool $has, mixed $caveats): Obj
    {
        $body = Obj::of(['issuer' => $kp->public, 'holder' => $kp->public]);
        if ($has) {
            $body->set('caveats', $caveats);
        }
        $body->set('parent', null);
        $digest = Pca::hashCanonical($body);
        $sig = Pca::b64u($kp->sign(Pca::CAP_DOMAIN . (Pca::unb64u($digest, 32) ?? '')));
        $cap = Obj::of(['id' => $digest, 'issuer' => $kp->public, 'holder' => $kp->public]);
        if ($has) {
            $cap->set('caveats', $caveats);
        }
        $cap->set('body_digest', $digest);
        $cap->set('sig', $sig);
        return $cap;
    }

    public function testControlEmptyListVerifies(): void
    {
        $kp = KeyPair::generate();
        $this->assertSame(['', true], Pca::verifyChain([self::root($kp, true, [])], $kp->public, true));
    }

    public function testNonArrayLeafCaveatsAreRefused(): void
    {
        $kp = KeyPair::generate();
        $cases = ['missing' => [false, null], 'null' => [true, null], 'object' => [true, new Obj()], 'string' => [true, 'x'], 'number' => [true, new Num('5')]];
        foreach ($cases as $name => [$has, $v]) {
            $r = Pca::verifyChain([self::root($kp, $has, $v)], $kp->public, true);
            $this->assertFalse($r[1], $name);
            $this->assertSame('hop 0: malformed capability', $r[0], $name);
        }
    }
}
