<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SignersMore.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SignersMore as S;
use PHPUnit\Framework\TestCase;

/** verifyThreshold's decision (the first failure is the reason, every signer-set and share shape refused), kid limits and the receipt ledger. */
final class CryptoSurvivorKill3SignersMoreTest extends TestCase
{
    private const MSG = 'atlas threshold message';

    private static function agent(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/signers-kill-3/agent', true));
    }

    private static function other(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/signers-kill-3/other', true));
    }

    private static function p(string $c): string
    {
        return Pca::b64u(str_repeat($c, 32));
    }

    /** @return list<Obj> */
    private static function set(?string $pq = null): array
    {
        $e = ['role' => 'agent', 'publicKey' => self::agent()->public];
        if ($pq !== null) {
            $e['pq_pk'] = $pq;
        }
        return [Obj::of($e)];
    }

    private static function share(): Obj
    {
        return S::signThresholdShare('agent', self::agent(), self::MSG, self::set(), 1);
    }

    private static function with(Obj $o, string $k, mixed $v): Obj
    {
        $c = $o->without();
        $c->set($k, $v);
        return $c;
    }

    /** @param list<mixed> $shares */
    private static function verify(array $shares, mixed $set = null, mixed $t = 1): array
    {
        return S::verifyThreshold(Obj::of(['shares' => $shares]), self::MSG, $set ?? self::set(), $t);
    }

    private static function bad(string $reason): array
    {
        return ['ok' => false, 'count' => 0, 'roles' => [], 'reason' => $reason];
    }

    /** A threshold other than 1, 2 or 3 is refused, the value shown as the reference shows it. */
    public function testInvalidThreshold(): void
    {
        $this->assertSame(self::bad('invalid threshold t=5 (must be 1, 2 or 3)'), self::verify([], null, 5));
        $this->assertSame(self::bad('invalid threshold t=<object> (must be 1, 2 or 3)'), self::verify([], null, new Obj()));
    }

    /** A non-list signer set counts as empty; a non-object entry is a malformed set. */
    public function testSignerSetShapes(): void
    {
        $this->assertSame(self::bad('only 0 distinct valid key(s), need 1'), self::verify([], 'x'));
        $this->assertSame(self::bad('malformed signer set'), self::verify([], ['x']));
    }

    /** Every registered PQ public-key length is accepted in a signer set; any other length is malformed. */
    public function testSignerSetPqKeyLengths(): void
    {
        foreach ([1952, 2592, 32, 64, 897, 1793, 97484] as $n) {
            $this->assertSame(self::bad('only 0 distinct valid key(s), need 1'), self::verify([], self::set(Pca::b64u(str_repeat('p', $n)))), "pq_pk of $n bytes");
        }
        $this->assertSame(self::bad('malformed signer set (pq_pk)'), self::verify([], self::set(Pca::b64u(str_repeat('p', 33)))));
    }

    /** A non-object signature or a non-list `shares` counts no shares. */
    public function testSignatureShapes(): void
    {
        $this->assertSame(self::bad('only 0 distinct valid key(s), need 1'), S::verifyThreshold('x', self::MSG, self::set(), 1));
        $this->assertSame(self::bad('only 0 distinct valid key(s), need 1'), S::verifyThreshold(Obj::of(['shares' => 'x']), self::MSG, self::set(), 1));
    }

    /** A share that is not an object with string role and publicKey is malformed, and does not stop later shares counting. */
    public function testMalformedSharesAreSkipped(): void
    {
        $this->assertSame(self::bad('malformed share'), self::verify(['x']));
        $this->assertSame(self::bad('malformed share'), self::verify([Obj::of(['role' => 5, 'publicKey' => 'k'])]));
        $this->assertSame(['ok' => true, 'count' => 1, 'roles' => ['agent']], self::verify(['x', self::share()]));
    }

    /** The FIRST failing share gives the reason; later failures never overwrite it. */
    public function testFirstFailureIsTheReason(): void
    {
        $this->assertSame(self::bad('role guardian is not in the signer set'), self::verify([Obj::of(['role' => 'guardian', 'publicKey' => 'k']), 'x']));
        $wrongKey = self::with(self::share(), 'publicKey', self::other()->public);
        $badAlg = self::with(self::share(), 'alg', 'bogus');
        $badSig = S::signThresholdShare('agent', self::agent(), self::MSG . '!', self::set(), 1);
        foreach ([$wrongKey, $badAlg, $badSig] as $later) {
            $this->assertSame(self::bad('malformed share'), self::verify(['x', $later]));
        }
        $this->assertSame(self::bad('malformed share'), self::verify(['x', self::with(self::share(), 'pq_pk', self::p('Q'))], self::set(self::p('P'))));
    }

    /** Each share refusal on its own, with its reason. */
    public function testShareRefusalReasons(): void
    {
        $this->assertSame(self::bad('share for role agent uses a key not registered for that role'),
            self::verify([self::with(self::share(), 'publicKey', self::other()->public)]));
        $this->assertSame(self::bad('share for role agent declares an unknown signature alg'), self::verify([self::with(self::share(), 'alg', 'bogus')]));
        $this->assertSame(self::bad('invalid signature for role agent'),
            self::verify([S::signThresholdShare('agent', self::agent(), self::MSG . '!', self::set(), 1)]));
    }

    /** A share naming a pq_pk must name exactly its role's registered one (a string equal to it); naming the right one passes to the signature check. */
    public function testSharePqKeyMustBeTheRegisteredOne(): void
    {
        $set = self::set(self::p('P'));
        $named = 'share for role agent names a pq_pk that is not the key its role registers';
        $this->assertSame(self::bad($named), self::verify([self::with(self::share(), 'pq_pk', self::p('Q'))], $set));
        $this->assertSame(self::bad($named), self::verify([self::with(self::share(), 'pq_pk', 5)], $set));
        // the registered pq_pk: on to the signature, which an Ed25519-only share cannot satisfy for a PQ-registered role
        $this->assertSame(self::bad('invalid signature for role agent'), self::verify([self::with(self::share(), 'pq_pk', self::p('P'))], $set));
    }

    /** A kid of 128 bytes is accepted, 129 is refused. */
    public function testKidLimit(): void
    {
        $k = self::agent();
        $kid = str_repeat('k', 128);
        $this->assertSame($kid, S::actionSchemaKeyOf($kid, $k)->get('kid'));
        $this->assertSame($kid, S::signActionSchema(self::doc(), $kid, $k)->get('sig')->get('kid'));
        foreach (['actionSchemaKeyOf: kid must be a non-empty string' => fn() => S::actionSchemaKeyOf($kid . 'k', $k),
            'signActionSchema: sig.kid must be a non-empty string' => fn() => S::signActionSchema(self::doc(), $kid . 'k', $k)] as $msg => $f) {
            try {
                $f();
                $this->fail("a 129-byte kid was accepted: $msg");
            } catch (\InvalidArgumentException $e) {
                $this->assertSame($msg, $e->getMessage());
            }
        }
    }

    /** A receipt without its ledger position is refused. */
    public function testAccReceiptNeedsLedger(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('signAccReceipt: the receipt needs its ledger position');
        S::signAccReceipt(Obj::of(['v' => 1]), self::agent());
    }

    private static function doc(): mixed
    {
        foreach (Vectors::load('producer-vectors.json')->get('cases') as $c) {
            if ($c->get('name') === 'action-schema') {
                return $c->get('args')->get('doc');
            }
        }
        throw new \LogicException('action-schema case');
    }
}
