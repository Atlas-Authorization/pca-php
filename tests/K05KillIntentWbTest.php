<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/IntentWb.php: every fail-closed catch-all (driven through the IntentWb::$faultHook seam) refuses
 * with its exact reason; decideOfferSet refuses a bad policy itself; the pinned site key is the FIRST kid match (the
 * reference's `find`); setNested refuses a path whose last segment exists; utf16Len counts UTF-16 code units; distinct is
 * exact string distinctness. Signed fixtures are IntentWbKillTest's own (called through reflection).
 */
final class K05KillIntentWbTest extends TestCase
{
    protected function setUp(): void
    {
        IntentWb::$faultHook = null;
    }

    protected function tearDown(): void
    {
        IntentWb::$faultHook = null;
    }

    private static function wb(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentWbKillTest::class, $m))->invokeArgs(null, $a);
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentWb::class, $m))->invokeArgs(null, $a);
    }

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    private static function throwAt(string $tag): void
    {
        IntentWb::$faultHook = static function (string $at) use ($tag): void {
            if ($at === $tag) {
                throw new \RuntimeException('boom');
            }
        };
    }

    public function testWorldCatchAllFailsClosed(): void
    {
        self::throwAt('world');
        $this->assertSame(['ok' => false, 'reason' => 'facts: evaluation error (fail closed): boom'], IntentWb::decideIntentWorld(new Obj()));
    }

    public function testOffersCatchAllFailsClosed(): void
    {
        self::throwAt('offers');
        $this->assertSame(['ok' => false, 'reason' => 'offers: evaluation error (fail closed): boom'],
            self::priv('decideOfferSet', self::o(self::wb('offersPolicy')), null, null, new Obj(), null, null, null, null));
        // through the public entry point the refusal is the facts check's
        $r = self::wb('od', self::wb('offerSet'));
        $this->assertFalse($r['ok']);
        $this->assertSame('facts: offers: evaluation error (fail closed): boom', $r['reason']);
    }

    public function testDecideOfferSetRefusesABadPolicyItself(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'offers: policy misconfigured (fail closed): offers policy must be an object'],
            self::priv('decideOfferSet', 'x', null, null, new Obj(), null, null, null, null));
        $this->assertSame(['ok' => false, 'reason' => 'offers: policy misconfigured (fail closed): offers policy needs at least one pinned site key'],
            self::priv('decideOfferSet', self::o(self::wb('offersPolicy', ['site_keys' => []])), null, null, new Obj(), null, null, null, null));
    }

    public function testPinnedSiteKeyIsTheFirstKidMatch(): void
    {
        $os = self::wb('offerSet');
        $osObj = self::o($os);
        $ref = IntentWb::offerSetRef($osObj);
        $params = self::o(self::wb('action'))->get('params');
        $good = ['kid' => 's1', 'pk' => self::wb('kp', 's1')[0]];
        $bad = ['kid' => 's1', 'pk' => self::wb('kp', 's2')[0]];
        $inner = fn(array $keys): array => self::priv('decideOfferSetInner', self::o(self::wb('offersPolicy', ['site_keys' => $keys])),
            $ref, $osObj, $params, 'skyair.example', self::wb('sess'), 1800000000000, 60000);
        $this->assertSame(['ok' => true, 'excess' => 1200, 'chosen_price' => 41000, 'min_price' => 39800], $inner([$good, $bad]));
        $this->assertSame(['ok' => false, 'reason' => 'offers: bad site signature'], $inner([$bad, $good]));
    }

    public function testProvenanceCatchAllFailsClosed(): void
    {
        self::throwAt('provenance');
        $r = IntentWb::decideParamProvenance(new Obj());
        $this->assertSame('deny', $r['outcome']);
        $this->assertSame('provenance: evaluation error (fail closed): boom', $r['reason']);
        $this->assertSame('{}', Json::canonicalizeStrict($r['labels']));
        $this->assertSame('{}', Json::canonicalizeStrict($r['env']));
    }

    public function testWbCatchAllFailsClosed(): void
    {
        self::throwAt('wb');
        $this->assertSame(['outcome' => 'deny', 'checks' => ['facts' => 'fail'], 'env' => [], 'reason' => 'facts: evaluation error (fail closed): boom'],
            IntentWb::decideIntentWb(new Obj()));
    }

    public function testSetNestedRefusesAnExistingLastSegment(): void
    {
        $root = self::o(['a' => ['b' => 'x']]);
        $this->assertFalse(self::priv('setNested', $root, 'a', 'v'));
        $this->assertFalse(self::priv('setNested', $root, 'a.b', 'v'));
        $this->assertSame('{"a":{"b":"x"}}', Json::canonicalizeStrict($root));
        $fresh = new Obj();
        $this->assertTrue(self::priv('setNested', $fresh, 'a.b', 'v'));
        $this->assertSame('{"a":{"b":"v"}}', Json::canonicalizeStrict($fresh));
    }

    public function testUtf16Len(): void
    {
        $this->assertSame(3, self::priv('utf16Len', 'abc'));
        $this->assertSame(3, self::priv('utf16Len', "\u{e9}\u{1F600}")); // 1 + a surrogate pair
        $this->assertSame(1, self::priv('utf16Len', "\xED\xA0\x80")); // WTF-8 lone surrogate
    }

    public function testDistinctIsExactStringDistinctness(): void
    {
        $this->assertTrue(self::priv('distinct', ['a', 'b', '1', '01', '1.0']));
        $this->assertFalse(self::priv('distinct', ['a', 'b', 'a']));
        $this->assertTrue(self::priv('distinct', []));
        $pol = fn(array $over): ?string => IntentWb::validateClassifierPolicy(self::o(['classifiers' => [self::wb('clsPolicy', $over)]]));
        $this->assertNull($pol([]));
        $this->assertSame("classifier 'tone': labels must be distinct non-empty strings", $pol(['labels' => ['neutral', 'other', 'neutral']]));
        $this->assertSame("classifier 'tone': keys must be distinct 32-byte keys", $pol(['keys' => [self::wb('kp', 'j1')[0], self::wb('kp', 'j1')[0]], 'k' => 1]));
    }
}
