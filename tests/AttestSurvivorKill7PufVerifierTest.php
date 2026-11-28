<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestPuf.php';

use Atlas\Pca\AttestPuf;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the PUF verifier: policy guard, enrollment expiry and the fail-closed error reason. */
final class AttestSurvivorKill7PufVerifierTest extends TestCase
{
    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return 'no error';
    }

    private static function expected(): Obj
    {
        return Obj::of(['holderPub' => 'hp', 'grantRef' => 'gr', 'epoch' => 1, 'nonce' => 'n1']);
    }

    /** @return array{0:Obj,1:Obj} enrollment and a valid statement for it */
    private static function device(): array
    {
        $puf = AttestPuf::createSimulatedPuf('dev-1', hash('sha256', 'atlas-pca-conformance/kill7-puf', true), 24);
        $rb = static fn(int $n): string => str_repeat("\x01", $n);
        $enr = AttestPuf::enrollPuf($puf, 'chal', Obj::of(['rep' => 3, 'messageBits' => 8, 'alg' => 'ed25519']), $rb);
        $st = AttestPuf::createPufAttestor($puf, $enr)(Obj::of(['measurement' => 'm1', 'holder_pub' => 'hp', 'grant_ref' => 'gr', 'epoch' => 1, 'nonce' => 'n1']));
        return [$enr, $st];
    }

    private static function verifier(Obj $enr, mixed $evidence): \Closure
    {
        return AttestPuf::createPufVerifier(Obj::of([
            'policy' => Obj::of(['measurements' => ['m1']]),
            'resolveEnrollment' => static fn() => $enr,
            'resolveEvidence' => $evidence,
        ]));
    }

    private static function input(mixed $nowMs): Obj
    {
        return Obj::of(['document' => new Obj(), 'ctx' => new Obj(), 'nowMs' => $nowMs, 'expected' => self::expected()]);
    }

    /** policy.measurements must be a non-empty list: a string, a keyed array or an empty list is refused; a real list builds. */
    public function testPolicyMeasurementsGuard(): void
    {
        $msg = 'TypeError: createPufVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)';
        $build = static fn(mixed $policy): string => self::thrown(static fn() => AttestPuf::createPufVerifier(Obj::of(['policy' => $policy, 'resolveEnrollment' => static fn() => null])));
        $this->assertSame($msg, $build(Obj::of(['measurements' => 'm1'])));
        $this->assertSame($msg, $build(Obj::of(['measurements' => ['a' => 'm1']])));
        $this->assertSame($msg, $build(Obj::of(['measurements' => []])));
        $this->assertSame($msg, $build(Obj::of([])));
        $this->assertSame('no error', $build(Obj::of(['measurements' => ['m1']])));
    }

    /** An enrollment with notAfter is expired for a non-finite or non-numeric clock and valid for a finite clock before it. */
    public function testExpiryRequiresAFiniteNumericClock(): void
    {
        [$enr, $st] = self::device();
        $dated = Jsx::spread($enr);
        $dated->set('notAfter', 10);
        $v = self::verifier($dated, static fn() => $st);
        $this->assertTrue($v(self::input(5))['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'PUF enrollment has expired'], $v(self::input(-INF)));
        $this->assertSame(['ok' => false, 'reason' => 'PUF enrollment has expired'], $v(self::input('5')));
        $this->assertSame(['ok' => false, 'reason' => 'PUF enrollment has expired'], $v(self::input(INF)));
        $this->assertSame(['ok' => false, 'reason' => 'PUF enrollment has expired'], $v(self::input(10)));
    }

    /** A throwing evidence resolver fails closed with its message, or with "unknown" when the message is empty. */
    public function testFailClosedReasonCarriesTheErrorMessage(): void
    {
        [$enr] = self::device();
        $boom = self::verifier($enr, static function (): never {
            throw new \RuntimeException('boom');
        });
        $this->assertSame(['ok' => false, 'reason' => 'puf verification error (fail closed): boom'], $boom(self::input(1)));
        $blank = self::verifier($enr, static function (): never {
            throw new \RuntimeException('');
        });
        $this->assertSame(['ok' => false, 'reason' => 'puf verification error (fail closed): unknown'], $blank(self::input(1)));
    }
}
