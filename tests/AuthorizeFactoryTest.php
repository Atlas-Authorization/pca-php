<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Authorize.php';
require_once __DIR__ . '/../src/StateStore.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\MemoryStateStore;
use PHPUnit\Framework\TestCase;

/** server/authorize.ts, verify.ts, authorize-execution.ts: createAuthorizer, the profile constants, enforceRequired, missingExecutionComponents. */
final class AuthorizeFactoryTest extends TestCase
{
    public function testIncompleteConfigRefusesEveryCall(): void
    {
        $az = Authorize::createAuthorizer(['audience' => 'rs']);
        $r = $az(['pcactn' => 'x', 'operation' => ['verb' => 'v', 'resource' => 'r', 'params' => []]]);
        self::assertFalse($r->allow);
        self::assertSame(403, $r->status);
        self::assertSame(['resolveGrant', 'stateStore', 'isRevoked'], $r->missing);
        self::assertSame('authorize: missing required component(s): resolveGrant, stateStore, isRevoked (fail closed)', $r->reason);
        self::assertSame('fail', $r->checks['authorize_config']);
    }

    public function testCompleteConfigNeverThrowsOnABadCall(): void
    {
        $az = Authorize::createAuthorizer(['audience' => 'rs', 'resolveGrant' => static fn() => null, 'stateStore' => new MemoryStateStore(), 'isRevoked' => static fn() => false]);
        $r = $az([]);
        self::assertFalse($r->allow);
        self::assertSame(403, $r->status);
        $r2 = $az(['pcactn' => 'not a pcactn', 'operation' => ['verb' => 'v', 'resource' => 'r', 'params' => new \Atlas\Pca\Obj()]]);
        self::assertFalse($r2->allow);
    }

    public function testProfilesAndEnforceRequired(): void
    {
        self::assertSame(['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound'], Authorize::STATEFUL_REQUIRED_CHECKS);
        self::assertSame([...Authorize::STATEFUL_REQUIRED_CHECKS, 'params_digest', 'policy'], Authorize::EXECUTION_REQUIRED_CHECKS);
        $v = ['allow' => true, 'checks' => ['audience' => 'pass', 'replay' => 'not-enforced', 'validity' => 'unsupported', 'x' => 'pass'], 'reasons' => []];
        $f = Authorize::enforceRequired($v, ['audience', 'counter', 'validity', 'revocation']);
        self::assertFalse($f['allow']);
        self::assertSame('pass', $f['checks']['audience']);
        self::assertSame('fail', $f['checks']['replay'], 'the legacy counter name resolves to replay');
        self::assertSame('unsupported', $f['checks']['validity']);
        self::assertSame('fail', $f['checks']['revocation']);
        self::assertSame(['replay: required check is not-enforced (default-deny: not enforced by this resource server)',
            'validity: required check is unsupported (default-deny: not enforced by this resource server)',
            'revocation: required check is absent (default-deny: not enforced by this resource server)'], $f['reasons']);
        self::assertSame('not-enforced', $v['checks']['replay'], 'the input is not mutated');
        self::assertTrue(Authorize::enforceRequired(['allow' => true, 'checks' => ['audience' => 'pass'], 'reasons' => []], ['audience'])['allow']);
        $cz = Authorize::enforceRequired(['allow' => true, 'checks' => ['counter_format' => 'pass'], 'reasons' => []], ['counter']);
        self::assertTrue($cz['allow']);
    }

    public function testMissingExecutionComponents(): void
    {
        self::assertSame(['audience', 'grant or resolveGrant', 'state', 'isRevoked'], Authorize::missingExecutionComponents(null));
        $ok = ['audience' => 'rs', 'resolveGrant' => static fn() => null, 'stateStore' => new MemoryStateStore(), 'isRevoked' => static fn() => false];
        self::assertSame([], Authorize::missingExecutionComponents($ok));
        self::assertSame([], Authorize::missingExecutionComponents(['grant' => 1] + array_diff_key($ok, ['resolveGrant' => 1])));
    }
}
