<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GroupDescriptor;
use Atlas\Pca\Num;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for GroupDescriptor: has(), String(x) in the reasons, the signer-set limits and the issue/verify refusals. */
final class SigSurvivorKill29GroupDescriptorTest extends TestCase
{
    private static function pk(string $label): string
    {
        return Pca::b64u(hash('sha256', "atlas-pca-conformance/g29-group/$label", true));
    }

    private static function parts(int $n): array
    {
        $out = [];
        for ($i = 1; $i <= $n; $i++) {
            $out[] = ['identifier' => $i, 'publicKey' => self::pk('share')];
        }
        return $out;
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/g29-group/authority', true);
    }

    private function threw(string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame(\InvalidArgumentException::class, $e::class);
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected: $message");
    }

    /** `k in o` only for an object or an assoc array: a list index or a scalar is never a member. */
    public function testHas(): void
    {
        $this->assertTrue(GroupDescriptor::has(['k' => null], 'k'));
        $this->assertFalse(GroupDescriptor::has(['a'], '0'));
        $this->assertFalse(GroupDescriptor::has('k', 'k'));
        $this->assertFalse(GroupDescriptor::has(null, 'k'));
    }

    /** show() is the reference's String(x). */
    public function testShowIsString(): void
    {
        $this->assertSame('2', GroupDescriptor::show(2));
        $this->assertSame('2', GroupDescriptor::show(new Num('2.0')));
        $this->assertSame('1.5', GroupDescriptor::show(1.5));
        $this->assertSame('1e+21', GroupDescriptor::show(1e21));
        $this->assertSame('Infinity', GroupDescriptor::show(INF));
        $this->assertSame('NaN', GroupDescriptor::show(NAN));
        $this->assertSame('0', GroupDescriptor::show(-0.0));
        $this->assertSame('null', GroupDescriptor::show(null));
        $this->assertSame('true', GroupDescriptor::show(true));
        $this->assertSame('false', GroupDescriptor::show(false));
        $this->assertSame('x', GroupDescriptor::show('x'));
        $this->assertSame('[object Object]', GroupDescriptor::show([]));
    }

    /** An impossible t is refused naming t and n as the reference prints them. */
    public function testIssueNamesABadThreshold(): void
    {
        $issue = fn (mixed $t) => GroupDescriptor::issueGroupDescriptor(self::seed(), self::pk('group'), $t, self::parts(1));
        $this->threw('issueGroupDescriptor: need 1 <= t <= n (t=Infinity, n=1)', fn () => $issue(INF));
        $this->threw('issueGroupDescriptor: need 1 <= t <= n (t=0, n=1)', fn () => $issue(-0.0));
        $this->threw('issueGroupDescriptor: need 1 <= t <= n (t=2, n=1)', fn () => $issue(2));
        $this->threw('issueGroupDescriptor: need 1 <= t <= n (t=true, n=1)', fn () => $issue(true));
    }

    /** issue refuses a non-list participant set and an authority key that is not 32 bytes. */
    public function testIssueRefusals(): void
    {
        $this->threw('issueGroupDescriptor: participants must be an array', fn () => GroupDescriptor::issueGroupDescriptor(self::seed(), self::pk('group'), 1, 'x'));
        $this->threw('issueGroupDescriptor: participants must be an array',
            fn () => GroupDescriptor::issueGroupDescriptor(self::seed(), self::pk('group'), 1, ['a' => self::parts(1)[0]]));
        $msg = 'issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key';
        $this->threw($msg, fn () => GroupDescriptor::issueGroupDescriptor('short', self::pk('group'), 1, self::parts(1)));
        $this->threw($msg, fn () => GroupDescriptor::issueGroupDescriptor(null, self::pk('group'), 1, self::parts(1)));
    }

    /** The signer set takes 1..1024 participants exactly, as a list of objects. */
    public function testSignerSetLimits(): void
    {
        $this->assertIsString(GroupDescriptor::signerSetCommitment(self::parts(GroupDescriptor::MAX_GROUP_SIZE)));
        $size = 'signerSetCommitment: need 1..1024 participants';
        $this->threw($size, fn () => GroupDescriptor::signerSetCommitment(self::parts(GroupDescriptor::MAX_GROUP_SIZE + 1)));
        $this->threw($size, fn () => GroupDescriptor::signerSetCommitment('x'));
        $this->threw($size, fn () => GroupDescriptor::signerSetCommitment(['a' => self::parts(1)[0]]));
        $this->threw('signerSetCommitment: participant is not an object', fn () => GroupDescriptor::signerSetCommitment(['x']));
    }

    /** A wire t or n of 2.0 is the same value as 2, so the signature still verifies; the pinned authorities must be a list. */
    public function testVerifyReadsValuesAndListPins(): void
    {
        $s = GroupDescriptor::issueGroupDescriptor(self::seed(), self::pk('group'), 2, self::parts(3));
        $pins = [$s['authority']];
        $this->assertTrue(GroupDescriptor::verifyGroupDescriptor($s, $pins, self::pk('group'), 2)['ok'], 'control');
        $s['descriptor']->set('t', new Num('2.0'));
        $s['descriptor']->set('n', new Num('3.0'));
        $this->assertTrue(GroupDescriptor::verifyGroupDescriptor($s, $pins, self::pk('group'), 2)['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'group descriptor could not be verified (malformed)'],
            GroupDescriptor::verifyGroupDescriptor($s, ['a' => $s['authority']], self::pk('group'), 2));
    }
}
