<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryUndoStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\UndoCoordinator;
use Atlas\Pca\UndoCoordinatorFactory;
use Atlas\Pca\UndoError;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/UndoCoordinator.php';

/**
 * The undo-window coordinator: admission, the durable record, the one-click veto, the compensation at most once, finalization and every
 * fail-closed refusal. Hand-written (no shared corpus exists for the coordinator in any language).
 */
final class UndoCoordinatorTest extends TestCase
{
    private const D43 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    private static function grant(): Obj
    {
        $env = ['predicates' => [['verb' => 'pay', 'resource' => 'invoice:*'], ['verb' => 'pay.refund', 'resource' => 'invoice:*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return Sign::mintGrant(new KeyPair(str_repeat("\x01", 32)), (new KeyPair(str_repeat("\x02", 32)))->public, $env, 'pay invoices', 's')['grant'];
    }

    private static function op(): Obj
    {
        return Obj::of(['verb' => 'pay', 'resource' => 'invoice:1', 'params' => Obj::of(['amount' => new Num('5')])]);
    }

    private static function action(Obj $grant, ?string $class = null): Obj
    {
        $params = Obj::of(['amount' => new Num('5')]);
        if ($class === null) {
            return (new Agent(new KeyPair(str_repeat("\x02", 32)), $grant, 'rs', null, 0, static fn() => 1000))->act('pay', 'invoice:1', $params)->pcactn;
        }
        // the signed class is the plan node's, so a non-default class needs a node that carries it
        $node = ['id' => 'n1', 'verb' => 'pay', 'resource' => 'invoice:1', 'params_digest' => Pca::paramsDigest(Sign::n($params)), 'reversibility_class' => $class];
        return Sign::buildPcactn($grant, [$grant], [$node], 'n1', 1, new KeyPair(str_repeat("\x02", 32)), 'rs', $params, 1000, null, Sign::DEFAULT_TTL_MS,
            ['nonce' => Pca::b64u(random_bytes(16))]);
    }

    private static function engine(?Obj $plan): object
    {
        return new class ($plan) {
            public function __construct(private readonly ?Obj $plan)
            {
            }

            public function plan(Obj $op, array $ctx): ?Obj
            {
                return $this->plan;
            }
        };
    }

    private static function plan(string $verb = 'pay.refund'): Obj
    {
        return Obj::of(['def_digest' => self::D43, 'compensation' => Obj::of(['verb' => $verb, 'params' => new Obj(), 'def_digest' => self::D43, 'target_param' => 'payment'])]);
    }

    private static function notifier(bool $deliver, array &$notices): object
    {
        return new class ($deliver, $notices) {
            public function __construct(private readonly bool $deliver, private array &$notices)
            {
            }

            public function notify(array $n): array
            {
                $this->notices[] = $n;
                return $this->deliver ? ['delivered' => true] : ['delivered' => false, 'reason' => 'no channel'];
            }
        };
    }

    private static function build(array &$clock, Obj $grant, array &$calls, array &$alerts, ?object $notifier = null, ?object $engine = null, array $extra = []): UndoCoordinator
    {
        $notices = [];
        $c = UndoCoordinatorFactory::create($extra + ['store' => new MemoryUndoStore(), 'engine' => $engine ?? self::engine(self::plan()), 'signerSecret' => str_repeat("\x09", 32),
            'audience' => 'rs', 'resolveGrant' => static fn($ref, $pc) => $grant, 'compensate' => static function (array $call) use (&$calls) {
                $calls[] = $call;
                return Obj::of(['refund' => 'r1']);
            }, 'operations' => new MemoryOperationStore(), 'notifier' => $notifier ?? self::notifier(true, $notices),
            'alert' => static function (array $a) use (&$alerts): void {
                $alerts[] = $a;
            }, 'now' => static function () use (&$clock) {
                return $clock[0];
            }, 'insecureVolatileStore' => true]);
        return $c;
    }

    public function testVetoWithTheTokenCompensatesOnce(): void
    {
        $grant = self::grant();
        $clock = [1000];
        $calls = $alerts = [];
        $c = self::build($clock, $grant, $calls, $alerts);
        $adm = $c->admit(self::action($grant), self::op(), false, $grant);
        $this->assertArrayNotHasKey('refused', $adm);
        $info = $c->open($adm);
        $this->assertSame('undo_window', $info['obligation']['kind']);
        $this->assertSame('open', $c->get($adm['id'])->get('state'));
        $c->recordEffect($adm['id'], Obj::of(['id' => 'pay_1']), true);
        $clock[0] = 2000;
        $v = $c->veto($adm['id'], $info['token']);
        $this->assertTrue($v['ok']);
        $this->assertSame('compensated', $v['record']->get('state'));
        $this->assertFalse($v['replayed']);
        $this->assertCount(1, $calls);
        $this->assertSame('pay_1', $calls[0]['operation']->get('params')->get('payment'));
        $again = $c->veto($adm['id'], $info['token']); // the same veto is a replay: the compensation never runs twice
        $this->assertTrue($again['ok']);
        $this->assertTrue($again['replayed']);
        $this->assertCount(1, $calls);
        $this->assertSame([], $alerts);
    }

    public function testATokenThatIsNotOneOrIsLateIsRefused(): void
    {
        $grant = self::grant();
        $clock = [1000];
        $calls = $alerts = [];
        $c = self::build($clock, $grant, $calls, $alerts);
        $adm = $c->admit(self::action($grant), self::op(), false, $grant);
        $info = $c->open($adm);
        $this->assertFalse($c->veto($adm['id'], 'not a token')['ok']);
        $clock[0] = $adm['window_end'] + 1;
        $this->assertFalse($c->veto($adm['id'], $info['token'])['ok']);
        $this->assertSame([], $calls);
    }

    public function testFinalizeClosesTheWindowAndAlertsAnUnreportedEffect(): void
    {
        $grant = self::grant();
        $clock = [1000];
        $calls = $alerts = [];
        $c = self::build($clock, $grant, $calls, $alerts);
        $adm = $c->admit(self::action($grant), self::op(), false, $grant);
        $c->open($adm);
        $this->assertSame([], $c->finalizeDue()); // the window is still open
        $clock[0] = $adm['window_end'] + 5;
        $this->assertSame([$adm['id']], $c->finalizeDue());
        $this->assertSame('finalized', $c->get($adm['id'])->get('state'));
        $this->assertSame(['effect_unknown'], array_column($alerts, 'code'));
        $this->assertSame([], $calls);
    }

    public function testAWindowNobodyWasToldAboutIsAborted(): void
    {
        $grant = self::grant();
        $clock = [1000];
        $n = [];
        $n = [];
        $calls = $alerts = [];
        $c = self::build($clock, $grant, $calls, $alerts, self::notifier(false, $n));
        $adm = $c->admit(self::action($grant), self::op(), false, $grant);
        try {
            $c->open($adm);
            $this->fail('open must refuse');
        } catch (UndoError) {
        }
        $this->assertSame('finalized', $c->get($adm['id'])->get('state'));
        $this->assertSame('notify_failed', $alerts[0]['code']);
        $this->assertSame('critical', $alerts[0]['level']);
    }

    public function testAdmissionRefusesWhatIsNotConfirmedReversible(): void
    {
        $grant = self::grant();
        $clock = [1000];
        $calls = $alerts = [];
        $c = self::build($clock, $grant, $calls, $alerts);
        $this->assertStringStartsWith('the signed class is irreversible', $c->admit(self::action($grant, 'irreversible'), self::op(), false, $grant)['refused']);
        $none = self::build($clock, $grant, $calls, $alerts, null, self::engine(null));
        $this->assertStringContainsString('not confirmed reversible', $none->admit(self::action($grant), self::op(), false, $grant)['refused']);
        $off = self::build($clock, $grant, $calls, $alerts, null, null, ['policy' => static fn() => ['mode' => 'off']]);
        $this->assertSame('policy: undo windows are off', $off->admit(self::action($grant), self::op(), false, $grant)['refused']);
        $esc = self::build($clock, $grant, $calls, $alerts, null, null, ['policy' => static fn() => ['mode' => 'escalations']]);
        $this->assertStringContainsString('windows only replace approvals', $esc->admit(self::action($grant), self::op(), false, $grant)['refused']);
        $this->assertArrayNotHasKey('refused', $esc->admit(self::action($grant), self::op(), true, $grant));
        $wide = self::build($clock, $grant, $calls, $alerts, null, self::engine(self::plan('admin.delete')));
        $this->assertStringContainsString('not authorized under the grant', $wide->admit(self::action($grant), self::op(), false, $grant)['refused']);
    }

    public function testAVolatileStoreAndMissingComponentsFailClosed(): void
    {
        $n = [];
        $base = ['store' => new MemoryUndoStore(), 'engine' => self::engine(null), 'signerSecret' => str_repeat("\x09", 32), 'audience' => 'rs',
            'resolveGrant' => static fn() => null, 'compensate' => static fn() => null, 'operations' => new MemoryOperationStore(), 'notifier' => self::notifier(true, $n),
            'alert' => static function (): void {
            }];
        try {
            UndoCoordinatorFactory::create($base);
            $this->fail('a volatile store must be refused');
        } catch (UndoError $e) {
            $this->assertSame('not_durable', $e->errorCode);
        }
        try {
            UndoCoordinatorFactory::create(array_diff_key($base, ['store' => 1, 'alert' => 1]));
            $this->fail('missing components must be refused');
        } catch (UndoError $e) {
            $this->assertSame('config', $e->errorCode);
            $this->assertStringContainsString('store, alert', $e->getMessage());
        }
    }
}
