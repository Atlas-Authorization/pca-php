<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalSign.php';

use Atlas\Pca\GoalSign;
use Atlas\Pca\KeyPair;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/GoalSign.php: signer coercion, the alg / pq options, and the fail-closed verification paths. */
final class GuardSurvivorKill33GoalSignTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/g33-goalsign', true);
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

    /** A Stringable secret is read as its seed string. */
    public function testStringableSecret(): void
    {
        $s = new class(self::seed()) implements \Stringable {
            public function __construct(private string $seed)
            {
            }

            public function __toString(): string
            {
                return $this->seed;
            }
        };
        $this->assertSame((new KeyPair(self::seed()))->public, GoalSign::signerId($s));
    }

    /** A string alg is passed to the signer (an unknown one refused); a non-string alg or pq option is ignored. */
    public function testAlgAndPqOptions(): void
    {
        $pk = GoalSign::signerId(self::seed());
        $this->assertSame("InvalidArgumentException: unknown signature alg 'bogus'", self::thrown(fn() => GoalSign::signPayload('k', 'p', self::seed(), ['alg' => 'bogus'])));
        foreach ([['alg' => 5], ['pq' => 'x'], ['alg' => 'ed25519']] as $opts) {
            $this->assertTrue(GoalSign::verifyPayload(GoalSign::signPayload('k', 'p', self::seed(), $opts), 'k', [$pk]), json_encode($opts));
        }
    }

    /** A supplied PQ key pair reaches the signer: one of the wrong family is refused for that reason, not as a missing key. */
    public function testPqKeyPairIsPassedOn(): void
    {
        $pq = (new \ReflectionClass(PqKeyPair::class))->newInstanceWithoutConstructor();
        \Closure::bind(function (): void {
            $this->family = 'ML-DSA-87';
            $this->public = 'x';
        }, $pq, PqKeyPair::class)();
        $this->assertSame('InvalidArgumentException: ml-dsa-65 needs a ML-DSA-65 key pair',
            self::thrown(fn() => GoalSign::signPayload('k', 'p', self::seed(), ['alg' => 'ml-dsa-65', 'pq' => $pq])));
    }

    /** Verification is total and fail closed: a non-object, a null pin, a non-list pin set; a non-string pin is skipped. */
    public function testVerifyRefusals(): void
    {
        $pk = GoalSign::signerId(self::seed());
        $a = GoalSign::signPayload('k', 'p', self::seed());
        $this->assertTrue(GoalSign::verifyGoalArtifact('k', $a, 'signer', [$pk]), 'control');
        $this->assertFalse(GoalSign::verifyGoalArtifact('k', 'not an object', 'signer', [$pk]));
        $this->assertFalse(GoalSign::verifyGoalArtifact('k', $a, 'signer', [null, $pk]));
        $this->assertFalse(GoalSign::verifyGoalArtifact('k', $a, 'signer', 'not a list'));
        $this->assertTrue(GoalSign::verifyGoalArtifact('k', $a, 'signer', [5, $pk]));
    }
}
