<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Authorize.php: the tool-call / caveat-context builders, the execution-config and enforceRequired folds, createAuthorizer. */
final class CoreSurvivorKill1AuthorizeTest extends TestCase
{
    private const CORE = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature',
        'counter_format'];

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    /** toolCallOf never throws on a context or action that is not an object: it is the empty tool call. */
    public function testToolCallOfNonObjectsIsTheEmptyCall(): void
    {
        foreach ([null, 'x', Obj::of(['action' => 'x', 'toolBinding' => 'd'])] as $ctx) {
            $t = Authorize::toolCallOf($ctx);
            self::assertSame('', $t['tool']);
            self::assertInstanceOf(Obj::class, $t['args']);
            self::assertSame([], $t['args']->keys());
        }
        self::assertArrayNotHasKey('toolSignatureDigest', Authorize::toolCallOf('x'));
        self::assertSame('d', Authorize::toolCallOf(Obj::of(['action' => 'x', 'toolBinding' => 'd']))['toolSignatureDigest']);
        $ok = Authorize::toolCallOf(Obj::of(['action' => Obj::of(['verb' => 'v', 'params' => Obj::of(['a' => 'b'])])]));
        self::assertSame('v', $ok['tool']);
        self::assertSame('b', $ok['args']->get('a'));
    }

    /** agentCaveatContext keeps the caller's base members, sets the derived action last, and tolerates non-object inputs. */
    public function testAgentCaveatContextKeepsTheBaseAndToleratesJunk(): void
    {
        $a = Obj::of(['verb' => 'v']);
        [$ctx] = Authorize::agentCaveatContext(Obj::of(['now' => 'n', 'action' => 'forged']), Obj::of(['action' => $a]));
        self::assertSame(['now', 'action'], $ctx->keys());
        self::assertSame('n', $ctx->get('now'));
        self::assertSame($a, $ctx->get('action'));
        [$ctx, $call] = Authorize::agentCaveatContext(null, 'x');
        self::assertSame(['action'], $ctx->keys());
        self::assertNull($ctx->get('action'));
        self::assertSame('', $call['tool']);
    }

    private static function store(): object
    {
        return new class {
            public function claim(string $key, int $counter): void
            {
            }
        };
    }

    /** `stateStore` wins over the legacy `state` alias, and an object without `claim` is no store. */
    public function testExecutionStateStoreResolution(): void
    {
        $base = ['audience' => 'rs', 'grant' => Obj::of([]), 'isRevoked' => static fn() => false];
        self::assertSame([], Authorize::missingExecutionComponents($base + ['stateStore' => self::store(), 'state' => 'junk']));
        self::assertSame([], Authorize::missingExecutionComponents($base + ['state' => self::store()]));
        self::assertSame(['state'], Authorize::missingExecutionComponents($base + ['stateStore' => new \stdClass()]));
    }

    /** enforceRequired keeps the verdict's own reasons and reads a missing `allow` as a denial. */
    public function testEnforceRequiredKeepsReasonsAndDefaultsToDeny(): void
    {
        self::assertSame(['allow' => true, 'checks' => ['a' => 'pass'], 'reasons' => ['r0']],
            Authorize::enforceRequired(['allow' => true, 'checks' => ['a' => 'pass'], 'reasons' => ['r0']], ['a']));
        self::assertSame(['allow' => false, 'checks' => ['a' => 'pass'], 'reasons' => []],
            Authorize::enforceRequired(['checks' => ['a' => 'pass']], ['a']));
    }

    /** @return array{0:array<string,mixed>,1:array<string,mixed>} [config, call] over the envelope-max-spend-within fixture */
    private static function fixture(): array
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $grant = $p = $op = null;
        foreach ($fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $grant = $c->get('grant');
                $p = $c->get('steps')[0]->get('pcactn');
                $op = $c->get('steps')[0]->get('operation');
            }
        }
        self::assertNotNull($grant);
        $config = ['audience' => $fix->get('audience'), 'resolveGrant' => static fn($ref) => $grant, 'stateStore' => new MemoryStateStore(),
            'isRevoked' => static fn() => false, 'now' => $fix->get('now')->int(), 'plan' => 'single-step',
            'provenance' => ProvHarness::bundle($op), 'provenanceMediators' => [ProvHarness::pin()], 'hard' => CalmRisk::hard()];
        return [$config, ['pcactn' => $p, 'operation' => $op]];
    }

    /** The built authorizer runs the configuration MERGED with the call; a call that cannot be bound is a typed fail-closed refusal. */
    public function testCreateAuthorizerMergesConfigAndCall(): void
    {
        Authorize::$coreHook = static function (array $c): array {
            return ['allow' => true, 'checks' => array_fill_keys(self::CORE, true), 'reason' => '', 'reasons' => []];
        };
        [$config, $call] = self::fixture();
        $az = Authorize::createAuthorizer($config);
        $r = $az($call);
        self::assertTrue($r->allow, implode('; ', $r->reasons));
        $bad = $az($call + ['noSuchOption' => 1]);
        self::assertFalse($bad->allow);
        self::assertSame(403, $bad->status);
        self::assertSame('authorize: error (fail closed): Error', $bad->reason);
        self::assertSame(['authorize' => 'fail'], $bad->checks);
    }
}
