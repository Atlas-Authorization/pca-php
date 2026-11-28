<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Aggsig;
use Atlas\Pca\KeyRegistry;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RegisteredKey;
use PHPUnit\Framework\TestCase;

/**
 * BLS aggregation: exact refusals, keyGen over an injected entropy source, the registry, the aggregated chain's per-hop checks, witness
 * cosignatures, and fail-closed behaviour when the blst library cannot be loaded. Needs ext-ffi and PCA_BLST_LIB (the pairing shard).
 */
final class GrantSurvivorKill21AggsigTest extends TestCase
{
    private const NO_LIB = 'BLS aggregation needs a built libblst (supranational/blst shared library; set PCA_BLST_LIB)';

    protected function setUp(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst)');
        }
    }

    protected function tearDown(): void
    {
        Aggsig::$randomHook = null;
    }

    private static function sk(string $label): string
    {
        $n = gmp_add(gmp_mod(gmp_init(bin2hex(hash('sha256', 'atlas-pca-conformance/g21-' . $label, true)), 16), gmp_sub(gmp_init(Aggsig::R_HEX, 16), 1)), 1);
        return hex2bin(str_pad(gmp_strval($n, 16), 64, '0', STR_PAD_LEFT));
    }

    private function assertThrown(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail('expected a throw');
    }

    private static function identityG1(): string
    {
        return "\xc0" . str_repeat("\0", 47);
    }

    private static function badG1(): string
    {
        return "\x9f" . str_repeat("\xff", 47); // x >= p: not a field element
    }

    /** @return array{0:RegisteredKey,1:KeyRegistry} */
    private static function registered(string $sk): array
    {
        $reg = new KeyRegistry();
        $r = $reg->register(Aggsig::publicKeyOf($sk), Aggsig::popProve($sk));
        return [$r['key'], $reg];
    }

    /** Key and message refusals carry their exact text. */
    public function testRefusalMessages(): void
    {
        $this->assertThrown(\InvalidArgumentException::class, 'invalid private key, expected 32 bytes, got 31', fn() => Aggsig::publicKeyOf(str_repeat("\1", 31)));
        $this->assertThrown(\InvalidArgumentException::class,
            'expected valid private key: 1 <= n < 52435875175126190479447740508185965837690552500527637822603658699938581184513',
            fn() => Aggsig::publicKeyOf(str_repeat("\0", 32)));
        $this->assertThrown(\TypeError::class, 'message: expected bytes', fn() => Aggsig::sign(self::sk('a'), 5));
        $this->assertFalse(Aggsig::canonicalSignature(5));
        $this->assertThrown(\InvalidArgumentException::class, 'aggregate: every signature must be a 96-byte compressed G2 point', fn() => Aggsig::aggregate([5]));
        $this->assertThrown(\InvalidArgumentException::class, 'aggregatePublicKeys: need at least one key', fn() => Aggsig::aggregatePublicKeys([]));
        $this->assertThrown(\InvalidArgumentException::class, 'aggregatePublicKeys: need at least one key', fn() => Aggsig::aggregatePublicKeys('x'));
        $this->assertThrown(\InvalidArgumentException::class, 'aggregatePublicKeys: not a G1 point', fn() => Aggsig::aggregatePublicKeys([self::badG1()]));
        $this->assertSame(Pca::b64u(Aggsig::publicKeyOf(self::sk('a'))), Aggsig::blsPublicKey(self::sk('a')));
    }

    /** keyGen reduces 48 entropy bytes mod r-1, adds 1, pads to 32 bytes, and refuses the degenerate key 1. */
    public function testKeyGenOverInjectedEntropy(): void
    {
        $asked = [];
        $x = str_repeat("\xff", 48);
        Aggsig::$randomHook = static function (int $n) use (&$asked, &$x): string {
            $asked[] = $n;
            return $x;
        };
        $k = Aggsig::keyGen();
        $secret = hex2bin('2dbeaf1fd4843acb7abbe5687369510cc7c884a6aae8978a07e08ed300000000');
        $this->assertSame(['secret_key' => $secret, 'public_key' => Aggsig::publicKeyOf($secret)], $k);
        $x = str_repeat("\0", 47) . "\x05";
        $this->assertSame(str_repeat("\0", 31) . "\x06", Aggsig::keyGen()['secret_key']);
        $x = str_repeat("\0", 48);
        $this->assertThrown(\RuntimeException::class, 'keyGen: entropy source produced the degenerate key 1 (RNG failure); refusing to continue', fn() => Aggsig::keyGen());
        $this->assertSame([48, 48, 48], $asked);
    }

    /** Signatures and proofs of possession verify; a non-byte message is false (never an escape). */
    public function testVerifyAndPop(): void
    {
        $sk = self::sk('a');
        $pk = Aggsig::publicKeyOf($sk);
        $sig = Aggsig::sign($sk, 'm');
        $this->assertTrue(Aggsig::verify($pk, 'm', $sig));
        $this->assertFalse(Aggsig::verify($pk, 5, $sig));
        $this->assertTrue(Aggsig::popVerify($pk, Aggsig::popProve($sk)));
    }

    /** Raw aggregate verification: keyed (non-list) inputs pair by position, every key is validated, a non-byte message is false. */
    public function testRawAggregateVerify(): void
    {
        [$a, $b] = [self::sk('a'), self::sk('b')];
        [$pa, $pb] = [Aggsig::publicKeyOf($a), Aggsig::publicKeyOf($b)];
        $agg = Aggsig::aggregate([Aggsig::sign($a, 'm1'), Aggsig::sign($b, 'm2')]);
        $this->assertTrue(Aggsig::rawAggregateVerify(['x' => $pa, 'y' => $pb], [5 => 'm1', 9 => 'm2'], $agg));
        $sig = Aggsig::sign($a, 'm');
        $this->assertFalse(Aggsig::rawAggregateVerify([self::badG1()], ['m'], $sig));
        $this->assertFalse(Aggsig::rawAggregateVerify([self::identityG1()], ['m'], $sig));
        $this->assertFalse(Aggsig::rawAggregateVerify([$pa], [5], $sig));
        $this->assertFalse(Aggsig::rawAggregateVerify([], [], $sig));
        // fast path: an identity key adds nothing to the sum but is still refused; a non-byte message is false
        $this->assertTrue(Aggsig::rawFastAggregateVerify([$pa], 'm', $sig));
        $this->assertFalse(Aggsig::rawFastAggregateVerify([$pa, self::identityG1()], 'm', $sig));
        $this->assertFalse(Aggsig::rawFastAggregateVerify([$pa], 5, $sig));
    }

    /** The registry: exact refusals and admission, lookups by exact 48-byte key, and keyed (non-list) key arrays refused. */
    public function testRegistry(): void
    {
        $sk = self::sk('a');
        $pk = Aggsig::publicKeyOf($sk);
        $pop = Aggsig::popProve($sk);
        $bad = ['ok' => false, 'reason' => 'public key and proof of possession must be Uint8Arrays'];
        $this->assertSame($bad, Aggsig::registerKey(5, $pop));
        $this->assertSame($bad, Aggsig::registerKey($pk, 5));
        $reg = new KeyRegistry();
        $r = $reg->register($pk, $pop);
        $this->assertSame(['ok', 'key'], array_keys($r));
        $this->assertTrue(Aggsig::isRegisteredKey($r['key']));
        $this->assertFalse(Aggsig::isRegisteredKey($pk));
        $this->assertSame([true, false, false, 1], [$reg->has($pk), $reg->has(5), $reg->has(Aggsig::publicKeyOf(self::sk('b'))), $reg->size()]);
        $sig = Aggsig::sign($sk, 'm');
        $this->assertTrue(Aggsig::aggregateVerify([$r['key']], ['m'], $sig));
        $this->assertTrue(Aggsig::fastAggregateVerify([$r['key']], 'm', $sig));
        $this->assertFalse(Aggsig::aggregateVerify(['k' => $r['key']], ['m'], $sig));
        $this->assertFalse(Aggsig::fastAggregateVerify(['k' => $r['key']], 'm', $sig));
        $this->assertFalse(Aggsig::aggregateVerify(['x'], ['m'], $sig));
    }

    private static function with(Obj $c, array $over): Obj
    {
        $o = new Obj();
        foreach ($c->keys() as $k) {
            $o->set($k, $c->get($k));
        }
        foreach ($over as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    /** @return array{0:Obj,1:KeyRegistry} */
    private static function root(): array
    {
        $sk = self::sk('a');
        [, $reg] = self::registered($sk);
        $root = Aggsig::mintBlsRoot($sk, Aggsig::blsPublicKey($sk), Aggsig::blsPublicKey(self::sk('b')), [Obj::of(['type' => 't1'])]);
        return [$root, $reg];
    }

    /** The chain's shape checks, exactly: hop count bound (16 is allowed), typed fields, list caveats of typed Obj, and the hop sig encoding. */
    public function testChainChecks(): void
    {
        [$root, $reg] = self::root();
        $agg = Aggsig::aggregateChainSignatures([$root]);
        $this->assertSame(['ok' => true], Aggsig::verifyAggregatedChain([$root], $agg, $reg));
        $reason = static fn(array $chain): ?string => Aggsig::verifyAggregatedChain($chain, $agg, $reg)['reason'] ?? null;
        $this->assertSame('hop 1: broken parent link', $reason(array_fill(0, 16, $root)));
        $this->assertSame('chain too long (max 16 hops)', $reason(array_fill(0, 17, $root)));
        $this->assertSame('empty chain', $reason(['a' => $root]));
        foreach ([['id' => 5], ['caveats' => 5], ['caveats' => [Obj::of(['x' => 1])]], ['caveats' => ['a' => Obj::of(['type' => 't1'])]]] as $over) {
            $this->assertSame('hop 0: malformed capability', $reason([self::with($root, $over)]), (string)json_encode(array_keys($over)));
        }
        $this->assertSame('malformed hop sig', $reason([self::with($root, ['sig' => Pca::b64u(str_repeat("\xff", 96))])]));
        $this->assertThrown(\InvalidArgumentException::class, 'aggregateChainSignatures: empty chain', fn() => Aggsig::aggregateChainSignatures([]));
        $this->assertThrown(\InvalidArgumentException::class, 'bad base64url', fn() => Aggsig::aggregateChainSignatures([self::with($root, ['sig' => '*'])]));
        $this->assertThrown(\InvalidArgumentException::class, 'bad base64url', fn() => Aggsig::aggregateChainSignatures([self::with($root, ['sig' => 5])]));
        // delegation keeps every parent caveat and appends every added one, in order
        $c2 = Obj::of(['type' => 't2']);
        $c3 = Obj::of(['type' => 't3']);
        $d = Aggsig::blsDelegate($root, 'h2', [$c2, $c3], self::sk('b'));
        $this->assertSame([$root->get('caveats')[0], $c2, $c3], $d->get('caveats'));
    }

    private static function statement(): Obj
    {
        return Obj::of(['size' => new Num('1'), 'root' => 'r', 'prev_root' => 'p']);
    }

    /** Witness cosignatures: a tree head without size is a TypeError; malformed inputs and key sets are false. */
    public function testWitnessCosignatures(): void
    {
        $sk = self::sk('a');
        [$rk] = self::registered($sk);
        $this->assertThrown(\TypeError::class, 'canonicalize: undefined value for size',
            fn() => Aggsig::cosignTreeHead(Obj::of(['root' => 'r', 'prev_root' => 'p']), $sk));
        $cos = Aggsig::cosignTreeHead(self::statement(), $sk);
        $this->assertTrue(Aggsig::verifyWitnessCosignature(self::statement(), $cos));
        $this->assertFalse(Aggsig::verifyWitnessCosignature(self::statement(), self::with($cos, ['key' => '*'])));
        $agg = Aggsig::aggregateWitnessCosignatures([$cos]);
        $this->assertTrue(Aggsig::verifyAggregatedWitnessCosignatures(self::statement(), [$rk], $agg));
        $this->assertFalse(Aggsig::verifyAggregatedWitnessCosignatures(self::statement(), 'x', $agg));
        $this->assertFalse(Aggsig::verifyAggregatedWitnessCosignatures(self::statement(), ['x'], $agg));
        $this->assertFalse(Aggsig::verifyAggregatedWitnessCosignatures(Obj::of(['root' => 'r', 'prev_root' => 'p']), [$rk], $agg));
        $this->assertThrown(\InvalidArgumentException::class, 'aggregateWitnessCosignatures: empty set', fn() => Aggsig::aggregateWitnessCosignatures([]));
    }

    /** With no loadable blst every verifier throws the library error (fail closed), never a quiet false. */
    public function testNoLibraryFailsClosed(): void
    {
        $a = self::sk('a');
        $pk = Aggsig::publicKeyOf($a);
        $sig = Aggsig::sign($a, 'm');
        $pop = Aggsig::popProve($a);
        [$rk] = self::registered($a);
        [$root, $reg] = self::root();
        $chainAgg = Aggsig::aggregateChainSignatures([$root]);
        $cos = Aggsig::cosignTreeHead(self::statement(), $a);
        $wAgg = Aggsig::aggregateWitnessCosignatures([$cos]);
        $calls = [
            'verify' => static fn() => Aggsig::verify($pk, 'm', $sig),
            'popVerify' => static fn() => Aggsig::popVerify($pk, $pop),
            'rawAggregateVerify' => static fn() => Aggsig::rawAggregateVerify([$pk], ['m'], $sig),
            'rawFastAggregateVerify' => static fn() => Aggsig::rawFastAggregateVerify([$pk], 'm', $sig),
            'verifyAggregatedChain' => static fn() => Aggsig::verifyAggregatedChain([$root], $chainAgg, $reg),
            'verifyWitnessCosignature' => static fn() => Aggsig::verifyWitnessCosignature(self::statement(), $cos),
            'verifyAggregatedWitnessCosignatures' => static fn() => Aggsig::verifyAggregatedWitnessCosignatures(self::statement(), [$rk], $wAgg),
        ];
        $prop = new \ReflectionProperty(Aggsig::class, 'ffi');
        $saved = $prop->getValue();
        $env = getenv('PCA_BLST_LIB');
        $seen = [];
        try {
            putenv('PCA_BLST_LIB=' . sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-g21-no-such-libblst-' . bin2hex(random_bytes(4)) . '.so');
            $prop->setValue(null, null);
            try {
                Aggsig::canonicalSignature($sig);
                $loaded = true;
            } catch (\RuntimeException) {
                $loaded = false;
            }
            if ($loaded) {
                $this->markTestSkipped('a libblst is on the system loader path, so the library cannot be made unavailable');
            }
            foreach ($calls as $name => $f) {
                try {
                    $f();
                    $seen[$name] = 'returned';
                } catch (\Throwable $e) {
                    $seen[$name] = get_class($e) . ': ' . $e->getMessage();
                }
            }
        } finally {
            putenv('PCA_BLST_LIB=' . $env);
            $prop->setValue(null, $saved);
        }
        $this->assertSame(array_fill_keys(array_keys($calls), 'RuntimeException: ' . self::NO_LIB), $seen);
    }
}
