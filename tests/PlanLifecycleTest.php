<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\PdoAtomicKv;
use Atlas\Pca\PlanRegistry;
use PHPUnit\Framework\TestCase;

/**
 * Plan lifecycle (T10): replays plan-vectors.json scenario by scenario (the roots are Merkle roots of the plan-node leaves, so a
 * match proves the commitment equals the reference's), then concurrent claims over a shared database, tampered stores and the
 * Authorize wiring. A missing vector file fails the test.
 */
final class PlanLifecycleTest extends TestCase
{
    public function testVectors(): void
    {
        [$n, $fails] = NativeParityVectors::plans();
        $this->assertSame([], $fails);
        $this->assertSame(87, $n);
    }

    private static function nodes(): array
    {
        return [['id' => 'n1', 'verb' => 'orders.read', 'resource' => '/orders/1']];
    }

    private function committed(PlanRegistry $reg, string $grant = 'g'): string
    {
        $d = $reg->draft($grant, self::nodes());
        $this->assertTrue($d['ok']);
        $root = $d['record']->get('root');
        $this->assertTrue($reg->validate($grant, $root)['ok']);
        $this->assertTrue($reg->commit($grant, $root)['ok']);
        return $root;
    }

    public function testEachTransitionHasExactlyOneWinnerSequentially(): void
    {
        $reg = new PlanRegistry(null, 'pca-plan:', fn () => 1000);
        $root = $this->committed($reg);
        $wins = 0;
        for ($i = 0; $i < 16; $i++) {
            $wins += $reg->authorize('g', $root, ['by' => 'p'])['ok'] ? 1 : 0;
        }
        $this->assertSame(1, $wins);
        $wins = 0;
        for ($i = 0; $i < 16; $i++) {
            $wins += $reg->revoke('g', $root, 'x')['ok'] ? 1 : 0;
        }
        $this->assertSame(1, $wins);
        $s = $reg->status('g', $root);
        $this->assertSame(['revoked', false], [$s['state'], $s['executable']]);
    }

    /** Of N processes sharing one database claiming one transition exactly one wins; the rest see the new state. */
    public function testConcurrentProcessesOneWinnerPerTransition(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        $db = tempnam(sys_get_temp_dir(), 'pcaplan');
        $open = static function () use ($db): PlanRegistry {
            $pdo = new \PDO('sqlite:' . $db);
            $pdo->exec('PRAGMA busy_timeout = 10000');
            $kv = new PdoAtomicKv($pdo);
            $kv->createTable();
            return new PlanRegistry($kv, 'pca-plan:', fn () => 1000);
        };
        $root = $this->committed($open());
        foreach (['authorize', 'revoke'] as $step) {
            $pids = [];
            for ($i = 0; $i < 16; $i++) {
                $pid = pcntl_fork();
                if ($pid === 0) {
                    $reg = $open();
                    $ok = $step === 'authorize' ? $reg->authorize('g', $root, ['by' => 'p'])['ok'] : $reg->revoke('g', $root, 'x')['ok'];
                    exit($ok ? 10 : 11);
                }
                $pids[] = $pid;
            }
            $codes = [];
            foreach ($pids as $pid) {
                pcntl_waitpid($pid, $status);
                $codes[] = pcntl_wexitstatus($status);
            }
            $this->assertSame(1, count(array_filter($codes, fn ($c) => $c === 10)), "$step: one winner");
            $this->assertSame(15, count(array_filter($codes, fn ($c) => $c === 11)), "$step: the rest see the new state");
        }
        $this->assertSame('revoked', $open()->status('g', $root)['state']);
        @unlink($db);
    }

    public function testDraftingOneRootTwiceHasOneWinnerAndTheKvsAgree(): void
    {
        foreach ([new MemoryAtomicKv(), new PdoAtomicKv((static function (): \PDO { return new \PDO('sqlite::memory:'); })())] as $kv) {
            if ($kv instanceof PdoAtomicKv) {
                $kv->createTable();
            }
            $reg = new PlanRegistry($kv);
            $wins = 0;
            for ($i = 0; $i < 8; $i++) {
                $wins += $reg->draft('g', self::nodes())['ok'] ? 1 : 0;
            }
            $this->assertSame(1, $wins);
        }
    }

    /** A tampered stored plan is never executable: the nodes must still hash to the root. */
    public function testStatusDetectsTamperedNodes(): void
    {
        $kv = new MemoryAtomicKv();
        $reg = new PlanRegistry($kv, 'pca-plan:', fn () => 5);
        $root = $this->committed($reg);
        $this->assertTrue($reg->authorize('g', $root, ['by' => 'p'])['ok']);
        $this->assertTrue($reg->status('g', $root)['executable']);
        $key = 'pca-plan:g:' . $root;
        $kv->update($key, fn (?string $prev) => str_replace('/orders/1', '/orders/2', (string)$prev));
        $s = $reg->status('g', $root);
        $this->assertFalse($s['executable']);
        $this->assertSame("plan $root: the stored nodes no longer hash to the root", $s['reason']);
    }

    public function testPlanStoreThatThrowsIsNotExecutable(): void
    {
        $broken = new class implements \Atlas\Pca\AtomicKv {
            public function get(string $key): ?string { throw new \RuntimeException('down'); }
            public function update(string $key, callable $fn): void { throw new \RuntimeException('down'); }
        };
        $reg = new PlanRegistry($broken);
        $this->assertFalse($reg->isPlanAuthorized('g', 'r'));
        $this->assertFalse($reg->status('g', 'r')['executable']);
        $this->assertFalse($reg->commit('g', 'r')['ok']);
    }

    // ---- Authorize wiring

    private function authorizeWith(PlanRegistry $reg, MemoryStateStore $store): \Atlas\Pca\AuthorizeResult
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $c = $fix->get('cases')[0];
        $s = $c->get('steps')[0];
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $fix->get('audience'), fn ($r) => $c->get('grant'), $store,
            fn ($p, $g) => false, $fix->get('now')->int(), null, null, null, null, null, [], null, null, null, null, null, null, $reg);
    }

    public function testAuthorizeFeedsFromThePlanRegistry(): void
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $p = $fix->get('cases')[0]->get('steps')[0]->get('pcactn');
        $a = $p->get('action');
        $node = Obj::of(['id' => $p->get('plan')->get('node_id'), 'verb' => $a->get('verb'), 'resource' => $a->get('resource'),
            'params_digest' => $a->get('params_digest'), 'reversibility_class' => $a->get('reversibility_class')]);
        $reg = new PlanRegistry(null, 'pca-plan:', fn () => $fix->get('now')->int());
        $grant = $p->get('grant_ref');

        $r = $this->authorizeWith($reg, new MemoryStateStore());
        $this->assertFalse($r->allow, 'an unknown plan denies');
        $this->assertSame('fail', $r->checks['plan_state'] ?? null);
        $this->assertSame('fail', $r->checks['plan_root_authorized'] ?? null);

        $d = $reg->draft($grant, [$node]);
        $this->assertTrue($d['ok']);
        $root = $d['record']->get('root');
        $this->assertSame($p->get('plan')->get('root'), $root, "the registry's root equals the PCActn's plan root");
        $reg->validate($grant, $root);
        $reg->commit($grant, $root);
        $r = $this->authorizeWith($reg, new MemoryStateStore());
        $this->assertFalse($r->allow, 'a committed plan does not execute');
        $this->assertSame('fail', $r->checks['plan_state'] ?? null);
        $this->assertStringContainsString('committed but not authorized by the principal', implode('|', $r->reasons));

        $reg->authorize($grant, $root, ['by' => 'principal']);
        $r = $this->authorizeWith($reg, new MemoryStateStore());
        $this->assertTrue($r->allow, (string)$r->reason);
        $this->assertSame('pass', $r->checks['plan_state']);

        $reg->revoke($grant, $root, 'changed my mind');
        $r = $this->authorizeWith($reg, new MemoryStateStore());
        $this->assertFalse($r->allow, 'a revoked plan does not execute');
        $this->assertSame('fail', $r->checks['plan_state'] ?? null);
    }
}
