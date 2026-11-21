<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\PlanRegistry;
use PHPUnit\Framework\TestCase;

/** Kills the PlanLifecycle.php mutation survivors: clock, decode guard, node display, structural checks, store failures, check(). */
final class K05KillPlanLifecycleTest extends TestCase
{
    private const DOWN = 'the plan store failed (fail closed): down';

    private static function nodes(): array
    {
        return [['id' => 'n1', 'verb' => 'orders.read', 'resource' => '/orders/1']];
    }

    private static function put(MemoryAtomicKv $kv, string $key, string $json): void
    {
        $kv->update($key, static fn(?string $p): string => $json);
    }

    /** Rewrite the stored record at `$key` through `$f(Obj): void`. */
    private static function edit(MemoryAtomicKv $kv, string $key, callable $f): void
    {
        $kv->update($key, static function (?string $p) use ($f): string {
            $o = Json::parseLax((string)$p);
            $f($o);
            return Json::canonicalizeLenient($o);
        });
    }

    private function authorized(PlanRegistry $reg, array $approval = ['by' => 'p'], ?array $nodes = null): string
    {
        $d = $reg->draft('g', $nodes ?? self::nodes());
        $this->assertTrue($d['ok']);
        $root = $d['record']->get('root');
        $this->assertTrue($reg->validate('g', $root)['ok']);
        $this->assertTrue($reg->commit('g', $root)['ok']);
        $this->assertTrue($reg->authorize('g', $root, $approval)['ok']);
        return $root;
    }

    public function testClock(): void
    {
        $before = (int)(microtime(true) * 1000);
        $d = (new PlanRegistry())->draft('g', self::nodes());
        $after = (int)(microtime(true) * 1000);
        $c = (int)$d['record']->get('createdAt')->lexeme;
        $this->assertGreaterThanOrEqual($before, $c);
        $this->assertLessThanOrEqual($after, $c);
        // a clock answering a float is truncated to int ms
        $d = (new PlanRegistry(null, 'pca-plan:', static fn() => 1500.9))->draft('g', self::nodes());
        $this->assertSame('1500', $d['record']->get('createdAt')->lexeme);
        // a clock that throws is never authorized
        $reg = new PlanRegistry(null, 'pca-plan:', static fn() => throw new \RuntimeException('clock'));
        $this->assertFalse($reg->isPlanAuthorized('g', 'r'));
    }

    public function testDecodeRefusesMalformedRecords(): void
    {
        $kv = new MemoryAtomicKv();
        $reg = new PlanRegistry($kv, 'pca-plan:', static fn() => 1);
        $this->assertNull($reg->get('g', 'nope'));
        foreach (['[]', '"x"', '{"nodes":[],"state":"draft"}', '{"root":"r","nodes":5,"state":"draft"}', '{"root":"r","nodes":[],"state":5}'] as $raw) {
            self::put($kv, 'pca-plan:g:r', $raw);
            $this->assertNull($reg->get('g', 'r'), $raw);
            $this->assertSame(['state' => 'unknown', 'executable' => false, 'reason' => 'plan r is unknown for this grant'], $reg->status('g', 'r'), $raw);
        }
    }

    public function testDraftNodes(): void
    {
        $reg = new PlanRegistry(null, 'pca-plan:', static fn() => 1);
        $bad = ['ok' => false, 'state' => 'unknown', 'reason' => 'the plan cannot be committed: a plan node cannot be hashed'];
        $this->assertSame($bad, $reg->draft('g', [5]));
        $this->assertSame($bad, $reg->draft('g', ['x']));
        // the nodes are re-indexed: a keyed array hashes like the list
        $a = $reg->draft('g', [7 => self::nodes()[0]]);
        $this->assertTrue($a['ok']);
        $b = (new PlanRegistry())->draft('g', self::nodes());
        $this->assertSame($b['record']->get('root'), $a['record']->get('root'));
    }

    public function testUnknownReversibilityClassIsShown(): void
    {
        $cases = [[null, 'null'], [true, 'true'], [false, 'false'], [7, '7'], ['weird', 'weird'], [['a' => 1], '[object Object]']];
        foreach ($cases as [$x, $shown]) {
            $reg = new PlanRegistry(null, 'pca-plan:', static fn() => 1);
            $d = $reg->draft('g', [['id' => 'n1', 'verb' => 'v', 'resource' => 'r', 'reversibility_class' => $x]]);
            $this->assertTrue($d['ok'], $shown);
            $root = $d['record']->get('root');
            $this->assertSame(['ok' => false, 'state' => 'draft',
                'reason' => "plan $root is invalid: node 'n1' has an unknown reversibility class '$shown'"], $reg->validate('g', $root), $shown);
        }
    }

    public function testValidateTamperedDrafts(): void
    {
        $cases = [
            '[]' => 'a plan needs at least one node',
            '["x"]' => 'every node needs an id',
            '[{"verb":"v","resource":"r"}]' => 'every node needs an id',
            '[{"id":"n1","verb":"v","resource":"r"}]' => 'the stored nodes no longer hash to the root',
        ];
        foreach ($cases as $nodes => $why) {
            $kv = new MemoryAtomicKv();
            $reg = new PlanRegistry($kv, 'pca-plan:', static fn() => 1);
            self::put($kv, 'pca-plan:g:r', '{"createdAt":1,"grantRef":"g","nodes":' . $nodes . ',"root":"r","state":"draft"}');
            $this->assertSame(['ok' => false, 'state' => 'draft', 'reason' => "plan r is invalid: $why"], $reg->validate('g', 'r'), $nodes);
        }
    }

    public function testValidatorWithoutOkRefuses(): void
    {
        $reg = new PlanRegistry(null, 'pca-plan:', static fn() => 1, static fn(Obj $r): array => ['reason' => 'nope']);
        $root = $reg->draft('g', self::nodes())['record']->get('root');
        $this->assertSame(['ok' => false, 'state' => 'draft', 'reason' => "plan $root is invalid: nope"], $reg->validate('g', $root));
    }

    public function testStoreFailuresFailClosedWithTheMessage(): void
    {
        $broken = new class implements AtomicKv {
            public function get(string $key): ?string { throw new \RuntimeException('down'); }
            public function update(string $key, callable $fn): void { throw new \RuntimeException('down'); }
        };
        $reg = new PlanRegistry($broken, 'pca-plan:', static fn() => 1);
        $refused = ['ok' => false, 'state' => 'unknown', 'reason' => self::DOWN];
        $this->assertSame($refused, $reg->draft('g', self::nodes()));
        $this->assertSame($refused, $reg->validate('g', 'r'));
        $this->assertSame($refused, $reg->commit('g', 'r'));
        $this->assertSame(['state' => 'unknown', 'executable' => false, 'reason' => self::DOWN], $reg->status('g', 'r'));

        // a store whose update never runs the closure: the draft answers its initial (successful) outcome
        $noop = new class implements AtomicKv {
            public function get(string $key): ?string { return null; }
            public function update(string $key, callable $fn): void {}
        };
        $d = (new PlanRegistry($noop, 'pca-plan:', static fn() => 1))->draft('g', self::nodes());
        $this->assertSame(['ok', 'record'], array_keys($d));
        $this->assertTrue($d['ok']);
    }

    public function testStatusExpiryAndRevocation(): void
    {
        $reg = new PlanRegistry(null, 'pca-plan:', static fn() => 50);
        $root = $this->authorized($reg, ['by' => 'p', 'expiresAt' => 100]);
        $this->assertTrue($reg->status('g', $root)['executable']);
        $this->assertTrue($reg->status('g', $root, 99)['executable']);
        $s = $reg->status('g', $root, 100);
        $this->assertFalse($s['executable']);
        $this->assertStringStartsWith("plan $root: the principal's approval expired at ", $s['reason']);
        $this->assertFalse($reg->status('g', $root, 200)['executable'], 'the caller-supplied now is used');

        $this->assertTrue($reg->revoke('g', $root, '')['ok']);
        $this->assertSame("plan $root is revoked (no reason given)", $reg->status('g', $root)['reason']);
    }

    public function testStatusOnTamperedAuthorizedRecords(): void
    {
        $kv = new MemoryAtomicKv();
        $reg = new PlanRegistry($kv, 'pca-plan:', static fn() => 5);
        $root = $this->authorized($reg);
        $key = 'pca-plan:g:' . $root;
        self::edit($kv, $key, static fn(Obj $o) => $o->set('approval', 'x'));
        $this->assertTrue($reg->status('g', $root)['executable'], 'a non-object approval has no expiry');
        self::edit($kv, $key, static fn(Obj $o) => $o->set('nodes', []));
        $s = $reg->status('g', $root);
        $this->assertSame(['state', 'executable', 'record', 'reason'], array_keys($s));
        $this->assertSame(['authorized', false, "plan $root: the stored nodes no longer hash to the root"], [$s['state'], $s['executable'], $s['reason']]);
    }

    public function testCheck(): void
    {
        $reg = new PlanRegistry(null, 'pca-plan:', static fn() => 5);
        $d = $reg->draft('g', self::nodes());
        $root = $d['record']->get('root');
        $reg->validate('g', $root);
        $reg->commit('g', $root);
        $s = $reg->check('g', $root, ['nodeId' => 'zz']);
        $this->assertFalse($s['executable']);
        $this->assertSame("plan $root is committed but not authorized by the principal", $s['reason']);

        $reg->authorize('g', $root, ['by' => 'p']);
        $this->assertTrue($reg->check('g', $root, ['operation' => ['verb' => 'orders.read', 'resource' => '/orders/1']])['executable']);
        $s = $reg->check('g', $root, ['operation' => ['verb' => 'orders.read', 'resource' => '/orders/1', 'params' => ['x' => NAN]]]);
        $this->assertFalse($s['executable']);
        $this->assertSame("plan $root: the operation's params cannot be hashed", $s['reason']);
    }

    /** With duplicate node ids (only reachable by forcing the state), the FIRST node with the id is the one compared. */
    public function testCheckUsesTheFirstNodeWithTheId(): void
    {
        $kv = new MemoryAtomicKv();
        $reg = new PlanRegistry($kv, 'pca-plan:', static fn() => 5);
        $d = $reg->draft('g', [['id' => 'n1', 'verb' => 'a', 'resource' => 'r1'], ['id' => 'n1', 'verb' => 'b', 'resource' => 'r2']]);
        $root = $d['record']->get('root');
        self::edit($kv, 'pca-plan:g:' . $root, static fn(Obj $o) => $o->set('state', 'authorized'));
        $this->assertTrue($reg->check('g', $root, ['nodeId' => 'n1', 'operation' => ['verb' => 'a', 'resource' => 'r1']])['executable']);
        $this->assertFalse($reg->check('g', $root, ['nodeId' => 'n1', 'operation' => ['verb' => 'b', 'resource' => 'r2']])['executable']);
    }

    /** structuralProblem refuses a non-array and a non-list array the same way (never a TypeError, never past the guard). */
    public function testStructuralProblemNonListNodes(): void
    {
        $m = new \ReflectionMethod(PlanRegistry::class, 'structuralProblem');
        $this->assertSame('a plan needs at least one node', $m->invoke(null, 'x'));
        $this->assertSame('a plan needs at least one node', $m->invoke(null, null));
        $this->assertSame('a plan needs at least one node', $m->invoke(null, ['a' => Obj::of(['id' => 'n1', 'verb' => 'v', 'resource' => 'r'])]));
        $this->assertSame('a plan needs at least one node', $m->invoke(null, []));
    }
}
