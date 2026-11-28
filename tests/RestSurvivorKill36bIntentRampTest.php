<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentRamp.php';

use Atlas\Pca\DetMath;
use Atlas\Pca\IntentDriftDetector;
use Atlas\Pca\IntentTrustRamp;
use PHPUnit\Framework\TestCase;

/** IntentDriftDetector parameter checks and the alarm boundary; IntentTrustRamp uses the caller's observation verifier. */
final class RestSurvivorKill36bIntentRampTest extends TestCase
{
    private static function refusal(array $o): string
    {
        try {
            new IntentDriftDetector($o);
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'accepted';
    }

    /** A non-number rho0, rho1 or h is a refused parameter (read as 0), never a type error; rho0 == rho1 is refused too. */
    public function testParameterRefusals(): void
    {
        self::assertSame('DriftDetector: need 0 < rho0 < rho1 < 1', self::refusal(['rho0' => 'x']));
        self::assertSame('DriftDetector: need 0 < rho0 < rho1 < 1', self::refusal(['rho1' => 'x']));
        self::assertSame('DriftDetector: h must be positive', self::refusal(['h' => 'x']));
        self::assertSame('DriftDetector: need 0 < rho0 < rho1 < 1', self::refusal(['rho0' => 0.2, 'rho1' => 0.2]));
        self::assertSame('accepted', self::refusal(['rho0' => 0.2, 'rho1' => 0.3]));
    }

    /** The alarm is raised when the statistic reaches h exactly. */
    public function testAlarmAtExactlyH(): void
    {
        $h = DetMath::detLn(0.25 / 0.02);
        $d = new IntentDriftDetector(['h' => $h]);
        $s = $d->update(true);
        self::assertSame($h, $s['statistic']);
        self::assertTrue($s['alarm']);
    }

    /** recordObservation uses the verifyObservation closure from the context and returns its refusal reason. */
    public function testCustomObservationVerifier(): void
    {
        $ramp = new IntentTrustRamp(new \stdClass());
        $r = $ramp->recordObservation(['x' => 1], ['verifyObservation' => static fn(mixed $o, mixed $opts): array => ['ok' => false, 'reason' => 'custom refusal']]);
        self::assertSame(['ok' => false, 'reason' => 'custom refusal'], $r);
    }
}
