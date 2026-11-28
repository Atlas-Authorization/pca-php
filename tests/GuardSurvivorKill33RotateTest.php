<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Rotate.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Rotate;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Rotate.php: chain / hop / clock / reason / record refusals keep their exact errors, and the compromise index bounds. */
final class GuardSurvivorKill33RotateTest extends TestCase
{
    private static function kp(string $l): KeyPair
    {
        return new KeyPair(hash('sha256', "atlas-pca-conformance/g33-rotate-$l", true));
    }

    /** root (P -> A), A -> B, B -> C. @return list<Obj> */
    private static function chain(): array
    {
        $root = Sign::mintRoot(self::kp('P'), self::kp('A')->public, []);
        $h1 = Sign::delegate($root, self::kp('A'), self::kp('B')->public);
        return [$root, $h1, Sign::delegate($h1, self::kp('B'), self::kp('C')->public)];
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return 'no error';
    }

    private static function agentRotate(array $extra): array
    {
        $c = self::chain();
        return Rotate::rotateAgentKey([$c[0], $c[1]], ['oldHolderSecret' => self::kp('A'), 'newKeyPair' => self::kp('D')] + $extra);
    }

    /** A chain that is not a list, a hop that is not an object, a hop with an empty id: each refused with its own error. */
    public function testChainAndHopShapes(): void
    {
        $this->assertSame('InvalidArgumentException: rotateAgentKey: empty chain', self::thrown(fn() => Rotate::rotateAgentKey('x', [])));
        $this->assertSame('InvalidArgumentException: rotateAgentKey: empty chain', self::thrown(fn() => Rotate::rotateAgentKey(['a' => self::chain()[0]], [])));
        $this->assertSame('TypeError: rotateAgentKey: a chain hop is not an object', self::thrown(fn() => Rotate::rotateAgentKey(['x'], [])));
        $bad = Obj::of(['id' => '', 'issuer' => 'i', 'holder' => 'h', 'caveats' => []]);
        $this->assertSame('TypeError: rotateAgentKey: malformed capability', self::thrown(fn() => Rotate::rotateAgentKey([$bad], [])));
    }

    /** now: -0 prints as 0, 1 stays 1; null and Infinity are refused; a non-string reason is refused. */
    public function testClockAndReason(): void
    {
        $this->assertSame(0, self::agentRotate(['now' => -0.0])['revocation']['revokedAt']);
        $this->assertSame(1, self::agentRotate(['now' => 1])['revocation']['revokedAt']);
        foreach ([null, INF] as $n) {
            $this->assertSame('TypeError: rotateAgentKey: now must be a finite number', self::thrown(fn() => self::agentRotate(['now' => $n])));
        }
        $this->assertSame('TypeError: reason must be a string', self::thrown(fn() => self::agentRotate(['now' => 1, 'reason' => 5])));
    }

    /** holderSecrets that is not a list is refused before any signing. */
    public function testHolderSecretsMustBeAList(): void
    {
        $c = self::chain();
        foreach (['x', ['a' => self::kp('A')]] as $s) {
            $this->assertSame('InvalidArgumentException: rotatePrincipalKey: expected one holderSecret per non-root hop',
                self::thrown(fn() => Rotate::rotatePrincipalKey(['chain' => [$c[0], $c[1]], 'oldPrincipalSecret' => self::kp('P'), 'holderSecrets' => $s,
                    'newPrincipalKeyPair' => self::kp('Q')])));
        }
    }

    /** An absent holder and the root holder are refused with different reasons, in both entry points. */
    public function testCompromiseIndexBounds(): void
    {
        $c = self::chain();
        $o = ['ancestorSecret' => self::kp('A'), 'newKeyPair' => self::kp('D')];
        $this->assertSame('InvalidArgumentException: revokeAndReissueSubtree: the holder is not in the chain', self::thrown(fn() => Rotate::revokeAndReissueSubtree($c, 'nobody', $o)));
        $this->assertStringStartsWith('InvalidArgumentException: revokeAndReissueSubtree: the compromised holder is the root holder',
            self::thrown(fn() => Rotate::revokeAndReissueSubtree($c, self::kp('A')->public, $o)));
        $this->assertSame('InvalidArgumentException: compromisedKeyFlow: the holder is not in the chain', self::thrown(fn() => Rotate::compromisedKeyFlow($c, 'nobody', $o)));
        $this->assertStringStartsWith('InvalidArgumentException: revokeAndReissueSubtree: the compromised holder is the root holder',
            self::thrown(fn() => Rotate::compromisedKeyFlow($c, self::kp('A')->public, $o)));
    }

    /** Only the compromised subtree is checked for the new key: re-issuing to an ancestor's holder key is allowed. */
    public function testNewKeyMayBeAnAncestorsHolder(): void
    {
        $c = self::chain();
        $r = Rotate::revokeAndReissueSubtree($c, self::kp('C')->public, ['ancestorSecret' => self::kp('B'), 'newKeyPair' => self::kp('A'), 'now' => 1]);
        $this->assertCount(3, $r['chain']);
        $this->assertSame(self::kp('A')->public, $r['chain'][2]->get('holder'));
    }

    /** applyRotation refuses a non-list capIds, a non-list re-issued chain and a non-object hop before touching the sink. */
    public function testApplyRotationShapes(): void
    {
        $sink = new \stdClass();
        $rec = Obj::of(['capIds' => ['c1']]);
        foreach (['x', ['a' => 'c1']] as $ids) {
            $this->assertSame('TypeError: applyRotation: capIds must be a list', self::thrown(fn() => Rotate::applyRotation($sink, Obj::of(['capIds' => $ids]))));
        }
        foreach (['x', ['a' => 'h']] as $re) {
            $this->assertSame('TypeError: applyRotation: reissued must be a chain', self::thrown(fn() => Rotate::applyRotation($sink, $rec, $re)));
        }
        $this->assertSame('TypeError: applyRotation: a re-issued hop is not an object', self::thrown(fn() => Rotate::applyRotation($sink, $rec, ['x'])));
    }
}
