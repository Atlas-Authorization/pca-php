<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestAllowlistAnchor.php';

use Atlas\Pca\AllowlistAnchorLog;
use Atlas\Pca\AttestAllowlistAnchor;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Ledger;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The allowlist transparency anchor: entry bounds, anchoring refusals, head freshness arithmetic, feed checks, exact refusal reasons and the pinned keys. */
final class AttestSurvivorKill7AnchorTest extends TestCase
{
    private const NOW = 1800000000000;
    private const ISS = 'iss';
    private const HYBRID = 'hybrid-ed25519-ml-dsa-65';

    private static function secret(): string
    {
        return hash('sha256', 'atlas-pca-conformance/kill7-anchor-guardian', true);
    }

    private static function entry(int $version = 1, string $issuer = self::ISS, string $d = 'A'): Obj
    {
        return Obj::of(['issuer' => $issuer, 'version' => $version, 'digest' => str_repeat($d, 43)]);
    }

    private static function log(): AllowlistAnchorLog
    {
        return AttestAllowlistAnchor::createLog('inst-1', 'principal-1');
    }

    private static function trust(): Obj
    {
        return Obj::of(['logKey' => (new KeyPair(self::secret()))->public, 'instanceId' => 'inst-1', 'principal' => 'principal-1']);
    }

    private static function opts(int $now = self::NOW, array $extra = [], ?Obj $trust = null): Obj
    {
        $o = Obj::of(['trust' => $trust ?? self::trust(), 'nowMs' => $now]);
        foreach ($extra as $k => $v) {
            $o->set($k, $v);
        }
        return $o;
    }

    /** One anchored entry, signed at `$at`: [verified, evidence]. */
    private static function anchored(int $at = self::NOW, int $version = 1): array
    {
        $ev = AttestAllowlistAnchor::anchorHead(self::log(), self::entry($version), self::secret(), $at);
        return [self::entry($version), $ev];
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

    private static function no(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    /** The anchored manifest verifies; the highest anchored version is a native int; entries() hands out copies. */
    public function testAnchoredManifestVerifiesAndEntriesAreCopies(): void
    {
        $log = self::log();
        $ev = AttestAllowlistAnchor::anchorHead($log, self::entry(), self::secret(), self::NOW);
        $r = AttestAllowlistAnchor::verify(self::entry(), $ev, self::opts());
        $this->assertTrue($r['ok']);
        $this->assertSame(1, $r['highestAnchoredVersion']);
        $this->assertSame(1, $log->entries()[0]->get('version'));
        $log->entries()[0]->set('version', 99);
        $this->assertSame(1, $log->entries[0]->get('version'));
    }

    /** The largest safe-integer version and a 200-character issuer are valid entries; anything that is not an object entry is malformed. */
    public function testEntryBounds(): void
    {
        $log = self::log();
        AttestAllowlistAnchor::anchorHead($log, self::entry(9007199254740991), self::secret(), self::NOW);
        AttestAllowlistAnchor::anchorHead($log, self::entry(1, str_repeat('i', 200)), self::secret(), self::NOW);
        $this->assertSame(9007199254740991, $log->entries[0]->get('version'));
        $this->assertSame(str_repeat('i', 200), $log->entries[1]->get('issuer'));
        $this->assertSame('TypeError: anchorAllowlistHead: malformed entry',
            self::thrown(static fn() => AttestAllowlistAnchor::anchorHead(self::log(), 'x', self::secret(), self::NOW)));
    }

    /** evidenceFor needs a signed head; a lower version is refused with both versions named. */
    public function testAnchoringRefusals(): void
    {
        $this->assertSame('LogicException: evidenceFor: log has no signed head', self::thrown(static fn() => AttestAllowlistAnchor::evidenceFor(self::log(), 0)));
        $log = self::log();
        AttestAllowlistAnchor::anchorHead($log, self::entry(2), self::secret(), self::NOW);
        $this->assertSame('RuntimeException: anchorAllowlistHead: version 1 is lower than the anchored 2',
            self::thrown(static fn() => AttestAllowlistAnchor::anchorHead($log, self::entry(1), self::secret(), self::NOW)));
    }

    /** Re-anchoring an identical entry on a log whose head was dropped signs a new head. */
    public function testReanchorWithoutAHeadSignsOne(): void
    {
        $log = self::log();
        AttestAllowlistAnchor::anchorHead($log, self::entry(), self::secret(), self::NOW);
        $log->latest = null;
        $ev = AttestAllowlistAnchor::anchorHead($log, self::entry(), self::secret(), self::NOW + 1);
        $this->assertInstanceOf(Obj::class, $ev->get('head'));
        $this->assertSame((float)(self::NOW + 1), Js::num($log->latest()->get('timestamp')));
    }

    /** nowMs that is not a number, a missing trust, and non-finite skew / age options are refused with their own reasons. */
    public function testOptionRefusals(): void
    {
        [$v, $ev] = self::anchored();
        $o = self::opts();
        $o->set('nowMs', 'x');
        $this->assertSame(self::no('bad-head', 'nowMs must be an integer'), AttestAllowlistAnchor::verify($v, $ev, $o));
        $this->assertSame(self::no('bad-head', "Cannot read properties of undefined (reading 'logKey')"),
            AttestAllowlistAnchor::verify($v, $ev, Obj::of(['nowMs' => self::NOW])));
        $this->assertSame(self::no('bad-head', 'clockSkewMs must be a finite number'), AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW, ['clockSkewMs' => 'x'])));
        $this->assertSame(self::no('bad-head', 'maxHeadAgeMs must be a finite number'), AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW, ['maxHeadAgeMs' => 'x'])));
    }

    /** A configured witness policy is enforced: a head without the cosignature is refused. */
    public function testWitnessPolicyIsEnforced(): void
    {
        [$v, $ev] = self::anchored();
        $t = self::trust();
        $t->set('witnesses', Obj::of(['threshold' => 1, 'witnessKeys' => [(new KeyPair(str_repeat("\x09", 32)))->public]]));
        $this->assertSame(self::no('bad-head', 'tree head is not signed by the pinned log key (or lacks the required witness cosignatures)'),
            AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW, [], $t)));
    }

    /**
     * Near 2^53 the skew is floored before it is added (now + 0.5 would round up to the head's timestamp) while maxHeadAgeMs is below
     * 2^52; from 2^52 on the raw skew is used.
     */
    public function testSkewIsFlooredOnlyForAnIntegralAgeWindow(): void
    {
        [$v, $ev] = self::anchored(9007199254740990);
        $this->assertSame(self::no('stale-head', 'tree head is timestamped in the future'),
            AttestAllowlistAnchor::verify($v, $ev, self::opts(9007199254740989, ['clockSkewMs' => 0.5])));
        $r = AttestAllowlistAnchor::verify($v, $ev, self::opts(9007199254740989, ['clockSkewMs' => 0.5, 'maxHeadAgeMs' => 4503599627370496]));
        $this->assertTrue($r['ok']);
    }

    /** A fractional maxHeadAgeMs is floored; the stale reason names the window (the default is 24 h). */
    public function testHeadAgeWindow(): void
    {
        [$v, $ev] = self::anchored();
        $r = AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW + 1001, ['maxHeadAgeMs' => 1000.5]));
        $this->assertFalse($r['ok']);
        $this->assertSame('stale-head', $r['code']);
        $this->assertTrue(AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW + 1000, ['maxHeadAgeMs' => 1000.5]))['ok']);
        $this->assertSame(self::no('stale-head', 'tree head is older than maxHeadAgeMs (1000)'),
            AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW + 1001, ['maxHeadAgeMs' => 1000])));
        $this->assertSame(self::no('stale-head', 'tree head is older than maxHeadAgeMs (86400000)'),
            AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW + 86400001)));
    }

    /** A feed shorter than the signed size, or one holding a non-entry, is a size mismatch. */
    public function testFeedShape(): void
    {
        [$v, $ev] = self::anchored();
        $want = self::no('feed-mismatch', 'entries do not match the signed tree size');
        $e = $ev->without();
        $e->set('entries', []);
        $this->assertSame($want, AttestAllowlistAnchor::verify($v, $e, self::opts()));
        $e->set('entries', ['x']);
        $this->assertSame($want, AttestAllowlistAnchor::verify($v, $e, self::opts()));
    }

    /** A version below the highest anchored one names both and the issuer. */
    public function testAnchoredRollbackReason(): void
    {
        $log = self::log();
        AttestAllowlistAnchor::anchorHead($log, self::entry(1), self::secret(), self::NOW);
        AttestAllowlistAnchor::anchorHead($log, self::entry(2, self::ISS, 'B'), self::secret(), self::NOW);
        $this->assertSame(self::no('anchored-rollback', "manifest version 1 < highest anchored 2 for 'iss'"),
            AttestAllowlistAnchor::verify(self::entry(1), AttestAllowlistAnchor::evidenceFor($log, 0), self::opts()));
    }

    /** A version above 10^15 is looked up by its integer digits (not a float's exponent form). */
    public function testLargeVersionIsFoundByItsDigits(): void
    {
        [$v, $ev] = self::anchored(self::NOW, 9007199254740991);
        $r = AttestAllowlistAnchor::verify($v, $ev, self::opts());
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
        $this->assertSame(9007199254740991, $r['highestAnchoredVersion']);
    }

    /** A post-quantum guardian head verifies only under the PQ key pinned in trust.pqPins. */
    public function testPinnedPqGuardianKey(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $pq = new PqKeyPair('ML-DSA-65', hash('sha256', 'atlas-pca-conformance/kill7-anchor-pq', true));
        $ev = AttestAllowlistAnchor::anchorHead(self::log(), self::entry(), self::secret(), self::NOW, self::HYBRID, $pq);
        $t = self::trust();
        $this->assertFalse(AttestAllowlistAnchor::verify(self::entry(), $ev, self::opts(self::NOW, [], $t))['ok']); // control: unpinned
        $t->set('pqPins', Obj::of([$t->get('logKey') => $pq->public]));
        $r = AttestAllowlistAnchor::verify(self::entry(), $ev, self::opts(self::NOW, [], $t));
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
    }

    /** Without trust.pqPins the witness policy's own pqPins pin a post-quantum witness cosignature. */
    public function testWitnessPolicyPinsApplyWithoutTrustPins(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        [$v, $ev] = self::anchored();
        $head = $ev->get('head');
        $w = new KeyPair(hash('sha256', 'atlas-pca-conformance/kill7-anchor-witness', true));
        $wpq = new PqKeyPair('ML-DSA-65', hash('sha256', 'atlas-pca-conformance/kill7-anchor-witness-pq', true));
        $wb = Obj::of(['instance_id' => $head->get('instance_id'), 'principal' => $head->get('principal'), 'size' => $head->get('size'),
            'root' => $head->get('root'), 'prev_root' => $head->get('prev_root'), 'guardian_epoch' => new Num('0')]);
        $cs = Sign::signArtifact(Ledger::STH_WITNESS_DOMAIN, $wb, $w, self::HYBRID, $wpq);
        $cs->set('key', $w->public);
        $head->set('witnesses', [$cs]);
        $t = self::trust();
        $t->set('witnesses', Obj::of(['threshold' => 1, 'witnessKeys' => [$w->public], 'pqPins' => Obj::of([$w->public => $wpq->public])]));
        $r = AttestAllowlistAnchor::verify($v, $ev, self::opts(self::NOW, [], $t));
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
    }
}
