<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** authorize-pq-pin-fixtures.json: server-side PQ pins end to end through Authorize::authorize (allow, status, pq_pin check, exact reason). */
final class K05HardPqPinFixturesTest extends TestCase
{
    public function testEveryCase(): void
    {
        $f = Vectors::load('authorize-pq-pin-fixtures.json');
        $cases = $f->get('cases');
        $this->assertGreaterThanOrEqual(9, count($cases));
        $pqOk = Pca::suiteImplemented('ml-dsa-65');
        $op = $f->get('operation');
        foreach ($cases as $c) {
            $n = $c->get('name');
            $grant = $c->get('grant');
            $isPq = $grant->has('alg') && $grant->get('alg') !== 'ed25519';
            $x = $c->get('expect');
            $r = Authorize::authorize(pcactn: $c->get('pcactn'), operation: ['verb' => $op->get('verb'), 'resource' => $op->get('resource'), 'params' => $op->get('params')],
                audience: $f->get('audience'), resolveGrant: static fn($ref) => $ref === $grant->get('id') ? $grant : null, stateStore: new MemoryStateStore(),
                isRevoked: static fn() => false, now: $f->get('now')->int(), plan: 'single-step', pqPins: $c->get('pq_pins'));
            if ($isPq && !$pqOk) {
                $this->assertFalse($r->allow, "$n: a native that cannot verify ML-DSA-65 never allows");
                continue;
            }
            $this->assertSame($x->get('allow'), $r->allow, "$n allow: " . json_encode($r->reasons));
            $this->assertSame((int)$x->get('status')->int(), $r->status, "$n status");
            $this->assertSame($x->get('checks')->get('pq_pin'), $r->checks['pq_pin'] ?? 'absent', "$n pq_pin");
            if ($x->has('reason')) {
                $this->assertContains($x->get('reason'), $r->reasons, "$n reason");
            }
            foreach ($x->get('failed_includes') as $name) {
                $this->assertSame('fail', $r->checks[$name] ?? null, "$n failed $name");
            }
        }
    }

    public function testInheritedOrNonStringPinStillPins(): void
    {
        $f = Vectors::load('authorize-pq-pin-fixtures.json');
        $c = null;
        foreach ($f->get('cases') as $x) {
            if ($x->get('name') === 'classical-grant-from-a-pinned-issuer-is-refused') {
                $c = $x;
            }
        }
        $grant = $c->get('grant');
        $op = $f->get('operation');
        foreach ([7, null, '', Obj::of([])] as $pin) {
            $r = Authorize::authorize(pcactn: $c->get('pcactn'), operation: ['verb' => $op->get('verb'), 'resource' => $op->get('resource'), 'params' => $op->get('params')],
                audience: $f->get('audience'), resolveGrant: static fn($ref) => $grant, stateStore: new MemoryStateStore(),
                isRevoked: static fn() => false, now: $f->get('now')->int(), plan: 'single-step', pqPins: Obj::of([$grant->get('issuer') => $pin]));
            $this->assertSame('fail', $r->checks['pq_pin'] ?? null, json_encode($pin));
        }
    }
}
