<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Mesh;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for Mesh: whole proofs (the shared valid/base vector, and a one-hop proof built here with fixed-seed keys whose
 * revocation set holds the leaf "key:"), plus the Merkle and caveat helpers at their exact boundaries.
 */
final class K05KillMeshTest extends TestCase
{
    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Mesh::class, $m))->invoke(null, ...$a);
    }

    private static function base(): Obj
    {
        foreach (Vectors::load('mesh-vectors.json')->get('mesh') as $r) {
            if ($r->get('name') === 'valid/base') {
                return $r;
            }
        }
        throw new \RuntimeException('no valid/base');
    }

    private static function with(Obj $o, array $set): Obj
    {
        $c = $o->without();
        foreach ($set as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    private static function wrap(Obj $o): object
    {
        return new class($o) {
            public function __construct(private Obj $o)
            {
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function keys(): array
            {
                return $this->o->keys();
            }
        };
    }

    private static function j(string $t): mixed
    {
        return Json::parseLax($t);
    }

    private static function h(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
    }

    private static function cp(mixed $a, mixed $b, array $path): Obj
    {
        $n = fn($x) => is_int($x) ? new Num((string)$x) : $x;
        return Obj::of(['oldSize' => $n($a), 'newSize' => $n($b), 'path' => $path]);
    }

    /** @return array{0: string, 1: string} [public b64u, secret] */
    private static function key(int $seed): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr($seed), 32));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function sign(string $sk, string $msg): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($msg, $sk));
    }

    /**
     * A valid one-hop mesh proof: a root capability (human -> agent, no caveats) in a one-leaf domain log, a head cosigned by
     * one witness, and a one-leaf revocation set {"key:"} that brackets both the capability id and "key:<issuer>".
     * @return array{0: Obj, 1: Obj} [proof, trust]
     */
    private static function built(): array
    {
        [$human, $hsk] = self::key(1);
        [$agent, $ask] = self::key(2);
        [$dom, $dsk] = self::key(3);
        [$wit, $wsk] = self::key(4);
        $now = new Num('1800000000000');
        $digest = Pca::hashCanonical(Obj::of(['issuer' => $human, 'holder' => $agent, 'caveats' => [], 'parent' => null]));
        $cap = Obj::of(['id' => $digest, 'issuer' => $human, 'holder' => $agent, 'body_digest' => $digest, 'caveats' => [],
            'sig' => self::sign($hsk, Pca::CAP_DOMAIN . Pca::unb64u($digest, 32))]);
        $capHash = Pca::capHash($cap);
        $logRoot = Pca::b64u(hash('sha256', "\x00" . Json::canonicalizeStrict($capHash), true));
        $revRoot = self::priv('bindRevRoot', 1, Pca::b64u(hash('sha256', "\x00" . Json::canonicalizeStrict('key:'), true)));
        $head = Obj::of(['domain' => $dom, 'size' => new Num('1'), 'root' => $logRoot, 'rev_root' => $revRoot, 'rev_size' => new Num('1'),
            'timestamp' => $now]);
        $hc = Json::canonicalizeStrict($head);
        $leaf = fn() => Obj::of(['index' => new Num('0'), 'size' => new Num('1'), 'path' => []]);
        $action = Obj::of(['type' => 'pay', 'resource' => '/r', 'service_domain' => $dom, 'nonce' => 'n', 'at' => $now]);
        $proof = Obj::of([
            'chain' => [$cap],
            'heads' => [Obj::of(['head' => $head, 'sig' => self::sign($dsk, Mesh::HEAD_DOMAIN . $hc),
                'cosigs' => [Obj::of(['witness' => $wit, 'sig' => self::sign($wsk, Mesh::COSIG_DOMAIN . $hc)])]])],
            'rev_leaves' => [Obj::of(['id' => 'key:', 'proof' => $leaf()])],
            'hops' => [Obj::of(['domain' => $dom, 'head' => new Num('0'), 'inclusion' => $leaf(), 'revocation' => Obj::of([
                // the leaf "key:" sits above the id when the id sorts first, else below it
                'cap' => Obj::of(['size' => new Num('1'), (strcmp($digest, 'key:') < 0 ? 'hi' : 'lo') => new Num('0')]),
                'issuer_key' => Obj::of(['size' => new Num('1'), 'lo' => new Num('0')]),
            ])])],
            'action' => $action,
            'action_sig' => self::sign($ask, Mesh::ACTION_DOMAIN . Json::canonicalizeStrict(Obj::of(['action' => $action, 'tip' => $capHash]))),
        ]);
        $trust = Obj::of(['humanPrincipal' => $human, 'witnesses' => [$wit], 'threshold' => new Num('1'), 'now' => $now,
            'allowedDomains' => [$dom], 'rootDomain' => $dom]);
        return [$proof, $trust];
    }

    // ---- whole proofs ---------------------------------------------------------------------------------------------------

    public function testAOneHopChainVerifiesAndItsIssuerKeyIsLookedUpByName(): void
    {
        [$proof, $trust] = self::built();
        // one capability is a legal chain; the issuer key "key:<human>" is not the revoked leaf "key:"
        $this->assertSame(['ok' => true, 'hop' => -1], Mesh::verify($proof, $trust));
        $this->assertSame(['ok' => true, 'hop' => -1], Mesh::verify($proof, self::with($trust, ['maxChainLength' => new Num('1')])));
        $this->assertSame(['ok' => false, 'reason' => 'chain length out of bounds', 'hop' => -1], Mesh::verify(self::with($proof, ['chain' => []]), $trust));
        // three revocation leaves exceed the 2-per-capability table bound
        $this->assertSame('evidence tables exceed chain size', Mesh::verify(self::with($proof, ['rev_leaves' => [null, null, null]]), $trust)['reason']);
    }

    public function testValidBaseProofEdits(): void
    {
        $r = self::base();
        $proof = $r->get('proof');
        $trust = $r->get('trust');
        $ok = ['ok' => true, 'hop' => -1];
        $this->assertSame($ok, Mesh::verify($proof, $trust));
        $malformed = ['ok' => false, 'reason' => 'malformed proof', 'hop' => -1];
        // a proof that answers like an Obj but is not one
        $this->assertSame($malformed, Mesh::verify(self::wrap($proof), $trust));
        // hops keyed by name are not a list
        $this->assertSame($malformed, Mesh::verify(self::with($proof, ['hops' => array_combine(['a', 'b', 'c', 'd'], $proof->get('hops'))]), $trust));
        // 256 cosignatures (3 real + padding) are allowed; 257 are not
        $heads = $proof->get('heads');
        $pad = fn(int $n) => self::with($proof, ['heads' => array_merge([self::with($heads[0], ['cosigs' => array_merge($heads[0]->get('cosigs'), array_fill(0, $n - 3, null))])], array_slice($heads, 1))]);
        $this->assertSame($ok, Mesh::verify($pad(256), $trust));
        $this->assertSame('source-domain anchor: malformed head', Mesh::verify($pad(257), $trust)['reason']);
        // 256 well-formed pin proofs (for a domain no head has) are allowed; 257 are not; a null entry is malformed
        $pp = fn(int $n) => self::with($proof, ['pin_proofs' => array_map(fn() => Obj::of(['domain' => 'zz', 'proof' => self::cp(0, 0, [])]), range(1, $n))]);
        $this->assertSame($ok, Mesh::verify($pp(256), $trust));
        $this->assertSame('malformed pin proofs', Mesh::verify($pp(257), $trust)['reason']);
        $this->assertSame(['ok' => false, 'reason' => 'malformed pin proofs', 'hop' => -1], Mesh::verify(self::with($proof, ['pin_proofs' => [null]]), $trust));
        // 9 revocation leaves for 4 capabilities exceed the table bound
        $this->assertSame('evidence tables exceed chain size', Mesh::verify(self::with($proof, ['rev_leaves' => array_fill(0, 9, null)]), $trust)['reason']);
        // pqPins that is not an object is ignored
        $this->assertSame($ok, Mesh::verify($proof, self::with($trust, ['pqPins' => 'x'])));
        $this->assertSame($ok, Mesh::verify($proof, self::with($trust, ['pqPins' => ['a', 'b']])));
    }

    public function testTrustKeepsOnlyStringPqPins(): void
    {
        $trust = self::with(self::base()->get('trust'), ['pqPins' => Obj::of(['k' => 'v', 'n' => new Num('1'), 'm' => 'w'])]);
        [$t, $err] = self::priv('validTrust', $trust);
        $this->assertSame('', $err);
        $this->assertSame(['k' => 'v', 'm' => 'w'], $t['pqPins']);
        [$t] = self::priv('validTrust', self::base()->get('trust'));
        $this->assertSame([], $t['pqPins']);
    }

    // ---- helpers at their boundaries ------------------------------------------------------------------------------------

    public function testValueAndShapeHelpers(): void
    {
        $this->assertTrue(self::priv('nat', new Num('9007199254740991')));
        $this->assertFalse(self::priv('nat', new Num('9007199254740992')));
        $this->assertFalse(self::priv('verifySig', 123, 'm', 'AAAA'));
        $this->assertSame('head is for a different domain', self::priv('checkCosignedHead', 'x', 'd', [], null));
        $strs = fn(int $n) => array_fill(0, $n, 'a');
        $this->assertTrue(self::priv('validConsistency', self::cp(0, 0, $strs(128))));
        $this->assertFalse(self::priv('validConsistency', self::cp(0, 0, $strs(129))));
        $this->assertFalse(self::priv('validConsistency', self::cp(0, 0, ['a', new Num('1')])));
        $this->assertTrue(self::priv('validConsistency', self::cp(0, 0, ['a', 'b'])));
        $incl = fn(int $n) => Obj::of(['index' => new Num('0'), 'size' => new Num('0'), 'path' => $strs($n)]);
        $this->assertTrue(self::priv('validInclusion', $incl(128)));
        $this->assertFalse(self::priv('validInclusion', $incl(129)));
    }

    public function testEffectiveAuthorityRefusesMalformedCaveatLists(): void
    {
        $this->assertSame('malformed proof', self::priv('effective', 'x')[1]);
        $this->assertSame('malformed proof', self::priv('effective', [new Num('1')])[1]);
        $this->assertSame('', self::priv('effective', [])[1]);
    }

    public function testNarrowingOfAudienceExpiryAndHops(): void
    {
        $e = fn(string $json) => self::priv('effective', self::j($json))[0];
        $n = fn(string $child, string $parent) => self::priv('narrows', $e($child), $e($parent));
        $this->assertTrue($n('[{"type":"audience","domains":["a"]}]', '[{"type":"audience","domains":["a","b"]}]'));
        $this->assertFalse($n('[{"type":"audience","domains":["a","c"]}]', '[{"type":"audience","domains":["a","b"]}]'), 'a wider audience');
        $this->assertTrue($n('[{"type":"expires","at":100}]', '[{"type":"expires","at":100}]'));
        $this->assertFalse($n('[]', '[{"type":"expires","at":100}]'), 'a dropped expiry');
        $this->assertFalse($n('[{"type":"expires","at":200}]', '[{"type":"expires","at":100}]'), 'a later expiry');
        $this->assertTrue($n('[{"type":"expires","at":-5}]', '[]'));
        $this->assertTrue($n('[{"type":"max_hops","n":4}]', '[{"type":"max_hops","n":4}]'));
        $this->assertFalse($n('[{"type":"max_hops","n":5}]', '[{"type":"max_hops","n":4}]'), 'more hops');
    }

    public function testRevocationLeavesAndNonMembership(): void
    {
        $id = 'id';
        $tree = Pca::b64u(hash('sha256', "\x00" . Json::canonicalizeStrict($id), true));
        $root = self::priv('bindRevRoot', 1, $tree);
        $leaf = fn(string $i) => Obj::of(['size' => new Num('1'), 'index' => new Num($i), 'path' => []]);
        $this->assertTrue(self::priv('leafOk', $root, 1, $id, $leaf('0')));
        $this->assertFalse(self::priv('leafOk', $root, 1, $id, $leaf('1')), 'index == size');
        $this->assertFalse(self::priv('leafOk', $root, 1, $id, 'x'));
        // a lo/hi that is not an object counts as absent
        $this->assertFalse(Mesh::nonMembership($root, Obj::of(['size' => new Num('1'), 'lo' => 'x']), 'zz'));
        $this->assertFalse(Mesh::nonMembership($root, Obj::of(['size' => new Num('1'), 'hi' => 'x']), 'a'));
    }

    public function testConsistencyBoundariesAndShape(): void
    {
        $c = fn(string $o, string $n, Obj $p) => self::priv('consistency', $o, $n, $p);
        $e = Pca::b64u(hash('sha256', '', true));
        $r1 = Pca::b64u(str_repeat("\x11", 32));
        $r2 = Pca::b64u(str_repeat("\x22", 32));
        $this->assertFalse($c($e, $e, self::cp('x', 0, [])));
        $this->assertTrue($c($e, $e, self::cp(0, 0, [])));
        $this->assertFalse($c($e, $r1, self::cp(0, 0, [])));
        $this->assertTrue($c($e, $r1, self::cp(0, 3, [])));
        $this->assertFalse($c($e, $e, self::cp(0, 0, array_fill(0, 129, $r1))));
        $this->assertTrue($c($r1, $r1, self::cp(1, 1, [])));
        $this->assertFalse($c($r1, $r2, self::cp(1, 1, [])));
        $this->assertFalse($c($r1, $r1, self::cp(1, 1, [$r1])));
        $this->assertFalse($c($r1, $r1, self::cp(2, 1, [])));
        // 1 -> 2 with an undecodable old root
        $b = str_repeat("\x22", 32);
        $this->assertTrue($c($r1, Pca::b64u(self::h(str_repeat("\x11", 32), $b)), self::cp(1, 2, [Pca::b64u($b)])));
        $this->assertFalse($c('!!!', Pca::b64u(self::h(str_repeat("\x11", 32), $b)), self::cp(1, 2, [Pca::b64u($b)])));
        // 3 -> 4: old root H(p2, p0), new root H(p2, H(p0, p1))
        [$p0, $p1, $p2, $p3] = [str_repeat("\x01", 32), str_repeat("\x02", 32), str_repeat("\x03", 32), str_repeat("\x04", 32)];
        $old = self::h($p2, $p0);
        $new = self::h($p2, self::h($p0, $p1));
        $path = array_map([Pca::class, 'b64u'], [$p0, $p1, $p2]);
        $this->assertTrue($c(Pca::b64u($old), Pca::b64u($new), self::cp(3, 4, $path)));
        $this->assertFalse($c($r1, Pca::b64u($new), self::cp(3, 4, $path)), 'the old root must match too');
        // a trailing step after the proof is exhausted, even with roots folded over it
        $this->assertFalse($c(Pca::b64u(self::h($p3, $old)), Pca::b64u(self::h($p3, $new)), self::cp(3, 4, [...$path, Pca::b64u($p3)])));
    }

    public function testUnsetCeilingsStartAtZero(): void
    {
        [$e, $why] = self::priv('effective', []);
        $this->assertSame('', $why);
        $this->assertSame(0.0, $e['maxAmount']);
        $this->assertSame(0.0, $e['expiresAt']);
        $this->assertSame(0.0, $e['maxHops']);
        $this->assertFalse($e['hasAmount'] || $e['hasExp'] || $e['hasHops']);

        [$t, $bad] = self::priv('validTrust', Obj::of(['humanPrincipal' => 'h', 'witnesses' => ['w'], 'threshold' => new Num('1'),
            'now' => new Num('0'), 'allowedDomains' => ['d'], 'rootDomain' => 'd']));
        $this->assertSame('', $bad);
        $this->assertFalse($t['hasActionAge']);
        $this->assertSame(0.0, $t['maxActionAge']);
    }

    /** Mesh's own consistency copy: every node is 32 bytes (the 31/33-byte forgery with oldSize 1 must not verify). */
    public function testMeshConsistencyRefusesNodesThatAreNot32Bytes(): void
    {
        $m = new \ReflectionMethod(Mesh::class, 'consistency');
        $h = static fn (string $l, string $r): string => hash('sha256', "\x01" . $l . $r, true);
        $cp = static fn (string $p): Obj => Obj::of(['oldSize' => new Num('1'), 'newSize' => new Num('2'), 'path' => [$p]]);
        $c = str_repeat("\x33", 32);
        foreach ([31, 32, 33] as $n) {
            $bad = str_repeat("\x44", $n);
            $ok = $n === 32;
            $this->assertSame($ok, $m->invoke(null, Pca::b64u($bad), Pca::b64u($h($bad, $c)), $cp(Pca::b64u($c))), "old root $n");
            $this->assertSame($ok, $m->invoke(null, Pca::b64u($c), Pca::b64u($h($c, $bad)), $cp(Pca::b64u($bad))), "path $n");
        }
    }
}
