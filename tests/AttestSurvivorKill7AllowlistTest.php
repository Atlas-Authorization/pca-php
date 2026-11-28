<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AtomicKv.php';
require_once __DIR__ . '/../src/AttestAllowlist.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\AttestAllowlist;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** A scripted AtomicKv: `get` answers from a queue (the last answer repeats), `update` hands `$cur` to the callback (or skips it) and records what it returned. */
final class Kill7ScriptKv implements AtomicKv
{
    /** @var list<?string> */
    public array $written = [];
    public int $calls = 0;

    /** @param list<?string> $gets */
    public function __construct(private array $gets, private ?string $cur = null, private bool $callFn = true, private ?string $throw = null)
    {
    }

    public function get(string $key): ?string
    {
        if ($this->throw !== null) {
            throw new \RuntimeException($this->throw);
        }
        return count($this->gets) > 1 ? array_shift($this->gets) : $this->gets[0];
    }

    public function update(string $key, callable $fn): void
    {
        if ($this->callFn) {
            $this->calls++;
            $this->written[] = $fn($this->cur);
        }
    }
}

/** The measurement-allowlist manifests: exact refusal reasons, number shapes, the safe-integer and entry-count bounds, and the durable high-water mark under concurrent writers. */
final class AttestSurvivorKill7AllowlistTest extends TestCase
{
    private const ISS = 'https://issuer.example';
    private const NOW = 5000;

    private static function kp(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/kill7-allowlist', true));
    }

    private static function body(int $version = 1, array $entries = []): Obj
    {
        return Obj::of(['version' => $version, 'issuedAt' => 1000, 'notBefore' => 1000, 'expiresAt' => 100000, 'entries' => $entries]);
    }

    private static function manifest(int $version = 1, string $issuer = self::ISS): Obj
    {
        return AttestAllowlist::sign(self::body($version), $issuer, 'ed25519', self::kp(), null);
    }

    private static function opts(string $issuer = self::ISS, string $alg = 'ed25519'): Obj
    {
        $keys = Obj::of([$issuer => Obj::of(['alg' => $alg, 'keys' => Obj::of(['edPub' => self::kp()->public])])]);
        return Obj::of(['issuerKeys' => $keys, 'nowMs' => self::NOW]);
    }

    private static function mrtd(int $i): Obj
    {
        return Obj::of(['kind' => 'tdx-mrtd', 'value' => str_pad(dechex($i), 96, '0', STR_PAD_LEFT), 'label' => 'x']);
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'no throw';
    }

    private static function digest(int $version = 1): string
    {
        $v = AttestAllowlist::verify(self::manifest($version), self::opts());
        if ($v['ok'] !== true) {
            throw new \LogicException('fixture does not verify');
        }
        return $v['digest'];
    }

    /** The largest safe integer is a valid version and every number of a created body (and an entry's notAfter) comes back a native int; 2^53 is refused. */
    public function testBodyNumbersAreNativeIntsUpToTheSafeIntegerBound(): void
    {
        $e = self::mrtd(1);
        $e->set('notAfter', 7000);
        $in = Obj::of(['version' => 9007199254740991, 'issuedAt' => 1000, 'notBefore' => 2000, 'expiresAt' => 100000, 'entries' => [$e]]);
        $b = AttestAllowlist::create($in);
        $this->assertSame(9007199254740991, $b->get('version'));
        $this->assertSame(1000, $b->get('issuedAt'));
        $this->assertSame(2000, $b->get('notBefore'));
        $this->assertSame(100000, $b->get('expiresAt'));
        $this->assertSame(7000, $b->get('entries')[0]->get('notAfter'));
        $in->set('version', 9007199254740992);
        $this->assertSame('TypeError: version must be a positive integer', self::thrown(static fn() => AttestAllowlist::create($in)));
    }

    /** A nowMs that is not a number is refused as malformed with its own reason (not a runtime error). */
    public function testNonNumericNowIsMalformedWithItsReason(): void
    {
        $o = self::opts();
        $o->set('nowMs', 'x');
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'nowMs must be an integer'], AttestAllowlist::verify(self::manifest(), $o));
    }

    /** Exactly MAX_ENTRIES (10000) entries are accepted; one more is refused. */
    public function testTheEntryBoundIsInclusive(): void
    {
        $entries = [];
        for ($i = 0; $i < 10000; $i++) {
            $entries[] = self::mrtd($i);
        }
        $this->assertCount(10000, AttestAllowlist::create(self::body(1, $entries))->get('entries'));
        $entries[] = self::mrtd(10000);
        $this->assertSame('TypeError: entries must be an array (bounded)', self::thrown(static fn() => AttestAllowlist::create(self::body(1, $entries))));
    }

    /** Entries that are not a list, an unknown kind and a non-string value are refused with their own messages. */
    public function testBodyShapeRefusalsKeepTheirMessages(): void
    {
        $b = self::body();
        $b->set('entries', 'x');
        $this->assertSame('TypeError: entries must be an array (bounded)', self::thrown(static fn() => AttestAllowlist::create($b)));
        $b->set('entries', [Obj::of(['kind' => 'bogus', 'value' => '', 'label' => 'x'])]);
        $this->assertSame('TypeError: entry 0: unknown kind', self::thrown(static fn() => AttestAllowlist::create($b)));
        $b->set('entries', [Obj::of(['kind' => 'tdx-mrtd', 'value' => 5, 'label' => 'x'])]);
        $this->assertSame('TypeError: entry 0: value and label must be strings', self::thrown(static fn() => AttestAllowlist::create($b)));
    }

    /** A pq_sig that is present but not a string is refused for its type, before the suite-presence check. */
    public function testNonStringPqSigIsRefusedForItsType(): void
    {
        $m = self::manifest();
        $m->set('pq_sig', 5);
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'pq_sig must be a string'], AttestAllowlist::verify($m, self::opts()));
    }

    /** An invalid body is refused with the body parser's message as the reason. */
    public function testInvalidBodyCarriesTheParserMessage(): void
    {
        $m = Obj::of(['body' => self::body(0), 'issuer' => self::ISS, 'alg' => 'ed25519', 'sig' => 'x']);
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'version must be a positive integer'], AttestAllowlist::verify($m, self::opts()));
    }

    /** Missing or null issuerKeys is a malformed call (not an unknown issuer); a non-object registry is an unknown issuer. */
    public function testIssuerRegistryShapes(): void
    {
        $want = ['ok' => false, 'code' => 'malformed', 'reason' => 'cannot convert undefined or null to object'];
        $this->assertSame($want, AttestAllowlist::verify(self::manifest(), Obj::of(['nowMs' => self::NOW])));
        $this->assertSame($want, AttestAllowlist::verify(self::manifest(), Obj::of(['nowMs' => self::NOW, 'issuerKeys' => null])));
        $this->assertSame(['ok' => false, 'code' => 'unknown-issuer', 'reason' => "issuer '" . self::ISS . "' is not registered"],
            AttestAllowlist::verify(self::manifest(), Obj::of(['nowMs' => self::NOW, 'issuerKeys' => 'x'])));
        $this->assertTrue(AttestAllowlist::verify(self::manifest(), self::opts())['ok']);
    }

    /** An algorithm downgrade names both the registered and the claimed algorithm. */
    public function testAlgMismatchReason(): void
    {
        $this->assertSame(['ok' => false, 'code' => 'alg-mismatch', 'reason' => "issuer is registered for 'ml-dsa-65', manifest claims 'ed25519'"],
            AttestAllowlist::verify(self::manifest(), self::opts(self::ISS, 'ml-dsa-65')));
    }

    /** A rollback below lastSeenVersion names both versions. */
    public function testRollbackReason(): void
    {
        $o = self::opts();
        $o->set('lastSeenVersion', 3);
        $this->assertSame(['ok' => false, 'code' => 'rollback', 'reason' => 'version 2 is older than last seen 3'], AttestAllowlist::verify(self::manifest(2), $o));
    }

    /** A stored high-water mark that is not an object is corrupt (a refusal, not a runtime error). */
    public function testNonObjectHighWaterIsCorrupt(): void
    {
        $kv = new MemoryAtomicKv();
        $kv->update('allowlist/' . self::ISS, static fn() => '[]');
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'persisted allowlist high-water mark is corrupt'],
            AttestAllowlist::verifyDurable(self::manifest(), self::opts(), $kv));
    }

    /** High-water versions 0 and negative integers are well-formed; -0 and a fraction are corrupt. */
    public function testHighWaterVersionShapes(): void
    {
        $d = str_repeat('A', 43);
        foreach (['0' => true, '-5' => true, '-0' => false, '1.5' => false] as $ver => $good) {
            $kv = new MemoryAtomicKv();
            $kv->update('allowlist/' . self::ISS, static fn() => '{"version":' . $ver . ',"digest":"' . $d . '"}');
            $r = AttestAllowlist::verifyDurable(self::manifest(), self::opts(), $kv);
            if ($good) {
                $this->assertTrue($r['ok'], "version $ver");
            } else {
                $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'persisted allowlist high-water mark is corrupt'], $r, "version $ver");
            }
        }
    }

    /** An issuer of exactly 200 characters is accepted by the durable verify; a non-string issuer is refused with its reason. */
    public function testDurableIssuerShape(): void
    {
        $iss = str_repeat('a', 200);
        $this->assertTrue(AttestAllowlist::verifyDurable(self::manifest(1, $iss), self::opts($iss), new MemoryAtomicKv())['ok']);
        $m = self::manifest();
        $m->set('issuer', 5);
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'issuer must be a string'], AttestAllowlist::verifyDurable($m, self::opts(), new MemoryAtomicKv()));
    }

    /** The stored mark feeds verify: a lower version is the verify rollback, the same version with another digest the verify conflict. */
    public function testStoredMarkIsPassedToVerify(): void
    {
        $kv = new MemoryAtomicKv();
        $kv->update('allowlist/' . self::ISS, static fn() => '{"version":2,"digest":"' . str_repeat('A', 43) . '"}');
        $this->assertSame(['ok' => false, 'code' => 'rollback', 'reason' => 'version 1 is older than last seen 2'], AttestAllowlist::verifyDurable(self::manifest(1), self::opts(), $kv));
        $this->assertSame(['ok' => false, 'code' => 'conflict', 'reason' => 'same version as last seen but a different body'],
            AttestAllowlist::verifyDurable(self::manifest(2), self::opts(), $kv));
    }

    /** A concurrent writer stored the same version with another body: conflict, and the stored mark is left alone. */
    public function testConcurrentSameVersionOtherBodyIsAConflict(): void
    {
        $kv = new Kill7ScriptKv([null], '{"version":1,"digest":"' . str_repeat('-', 43) . '"}');
        $this->assertSame(['ok' => false, 'code' => 'conflict', 'reason' => 'same version as the stored high-water mark but a different body'],
            AttestAllowlist::verifyDurable(self::manifest(1), self::opts(), $kv));
        $this->assertSame([null], $kv->written);
    }

    /** A concurrent writer stored a newer version or a corrupt record: rollback, and nothing is written over it. */
    public function testConcurrentNewerOrCorruptIsARollbackWithoutAWrite(): void
    {
        foreach (['{"version":5,"digest":"' . str_repeat('A', 43) . '"}', '[]'] as $cur) {
            $kv = new Kill7ScriptKv([null], $cur);
            $this->assertSame(['ok' => false, 'code' => 'rollback', 'reason' => 'a newer manifest was accepted concurrently'],
                AttestAllowlist::verifyDurable(self::manifest(1), self::opts(), $kv), $cur);
            $this->assertSame([null], $kv->written, $cur);
        }
    }

    /** A fresh store accepts and writes the mark, without re-reading the store afterwards. */
    public function testFreshStoreAdvancesTheMark(): void
    {
        $kv = new Kill7ScriptKv([null]);
        $r = AttestAllowlist::verifyDurable(self::manifest(1), self::opts(), $kv);
        $this->assertTrue($r['ok']);
        $this->assertCount(1, $kv->written);
        $j = json_decode((string)$kv->written[0], true);
        $this->assertSame(1, $j['version']);
        $this->assertSame($r['digest'], $j['digest']);
    }

    /** When the store never ran the callback, the decision is taken over what is stored now: our own mark is accepted, a newer one is a rollback. */
    public function testUpdateWithoutCallbackDecidesOverTheStoredRecord(): void
    {
        $d = self::digest(1);
        $kv = new Kill7ScriptKv([null, '{"version":1,"digest":"' . $d . '"}'], null, false);
        $r = AttestAllowlist::verifyDurable(self::manifest(1), self::opts(), $kv);
        $this->assertTrue($r['ok']);
        $this->assertSame($d, $r['digest']);
        $kv = new Kill7ScriptKv([null, '{"version":5,"digest":"' . $d . '"}'], null, false);
        $this->assertSame(['ok' => false, 'code' => 'rollback', 'reason' => 'a newer manifest was accepted concurrently'], AttestAllowlist::verifyDurable(self::manifest(1), self::opts(), $kv));
        $this->assertSame(0, $kv->calls);
    }

    /** A store that throws is a malformed refusal carrying the store's message. */
    public function testStoreErrorCarriesItsMessage(): void
    {
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'reason' => 'boom'],
            AttestAllowlist::verifyDurable(self::manifest(), self::opts(), new Kill7ScriptKv([null], null, true, 'boom')));
    }

    /** revokeEntry on entries that are not a list throws its own TypeError. */
    public function testRevokeEntryNeedsAList(): void
    {
        $this->assertSame('TypeError: prev.entries.map is not a function', self::thrown(static fn() => AttestAllowlist::revokeEntry(
            Obj::of(['version' => 1, 'entries' => 'x']), Obj::of(['kind' => 'tdx-mrtd', 'value' => 'v']), new Obj())));
    }

    /** project: non-iterable entries throw; an explicit revoked:false is not a tombstone; with no nowMs an entry with notAfter is expired. */
    public function testProjectEdgeShapes(): void
    {
        $this->assertSame('TypeError: entries is not iterable', self::thrown(static fn() => AttestAllowlist::project(
            Obj::of(['body' => Obj::of(['version' => 1, 'expiresAt' => 9, 'entries' => 'x'])]), Obj::of(['nowMs' => 1]))));
        $e = Obj::of(['kind' => 'tdx-mrtd', 'value' => 'v', 'label' => 'l', 'revoked' => false]);
        $p = AttestAllowlist::project(Obj::of(['body' => Obj::of(['version' => 1, 'expiresAt' => 9, 'entries' => [$e]])]), Obj::of(['nowMs' => 1]));
        $this->assertSame(['v'], $p['tdxMrtds']);
        $this->assertSame([], $p['revoked']);
        $e = Obj::of(['kind' => 'tdx-mrtd', 'value' => 'w', 'label' => 'l', 'notAfter' => 5]);
        $p = AttestAllowlist::project(Obj::of(['body' => Obj::of(['version' => 1, 'expiresAt' => 9, 'entries' => [$e]])]), new Obj());
        $this->assertSame([], $p['tdxMrtds']);
        $this->assertCount(1, $p['expired']);
        $this->assertSame('w', $p['expired'][0]->get('value'));
    }

    /** The policy-field lists are re-indexed lists even when the projection holds a keyed array. */
    public function testPolicyListsAreReindexed(): void
    {
        $this->assertSame(['x'], AttestAllowlist::sevSnpPolicyFields(Obj::of(['sevSnpMeasurements' => ['a' => 'x']]))->get('measurements'));
    }
}
