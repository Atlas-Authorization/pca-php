<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** pq-pin-vectors.json: server-side PQ pins at the authorize pipeline (`pq_pin` check status and reason). */
final class K05HardPqPinVectorsTest extends TestCase
{
    private static function vector(string $name): Obj
    {
        foreach (Vectors::load('vectors.json')->get('vectors') as $v) {
            if ($v->get('name') === $name) {
                return $v;
            }
        }
        throw new \RuntimeException("no vector $name");
    }

    public function testEveryRow(): void
    {
        $rows = Vectors::load('pq-pin-vectors.json')->get('pq_pin');
        $this->assertGreaterThanOrEqual(8, count($rows));
        foreach ($rows as $c) {
            $v = self::vector($c->get('vector'));
            $grant = $v->get('grant');
            if ($grant->has('alg') && $grant->get('alg') !== 'ed25519' && !\Atlas\Pca\Pca::suiteImplemented($grant->get('alg'))) {
                continue; // this runtime cannot verify the suite: the authorize pipeline fails before pq_pin
            }
            $issuer = $grant->get('issuer');
            $pk = $grant->get('pq_pk');
            $sub = static function (mixed $x) use ($pk): mixed {
                return match ($x) {
                    '$grant.pq_pk' => $pk,
                    '$grant.pq_pk[0:20]' => is_string($pk) ? substr($pk, 0, 20) : $pk,
                    default => $x,
                };
            };
            $pins = null;
            if ($c->get('pq_pins') !== null) {
                $pins = new Obj();
                foreach ($c->get('pq_pins')->keys() as $k) {
                    $pins->set($k === '$grant.issuer' ? $issuer : $k, $sub($c->get('pq_pins')->get($k)));
                }
            }
            $p = $v->get('pcactn');
            $action = $p->get('action');
            $ctx = $v->get('context');
            $r = Authorize::authorize(pcactn: $p, operation: ['verb' => $action->get('verb'), 'resource' => $action->get('resource'), 'params' => new Obj()],
                audience: $ctx->get('aud'), resolveGrant: static fn($ref) => $grant, stateStore: new MemoryStateStore(),
                isRevoked: static fn() => false, now: $ctx->get('now')->int(), plan: 'single-step', pqPins: $pins);
            $x = $c->get('expect');
            $name = $c->get('name');
            $this->assertSame($x->get('check'), $r->checks['pq_pin'] ?? 'absent', "$name status");
            if ($x->has('reason')) {
                $this->assertContains($x->get('reason'), $r->reasons, "$name reason");
            }
        }
    }
}
