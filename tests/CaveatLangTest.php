<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\CaveatLang;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\PdoStateStore;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\Pca;
use GuzzleHttp\Psr7\ServerRequest;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Caveat language v2: exact outcomes the shared vectors cannot show (hostile non-object inputs, hop positions, Kleene
 * unknowns, the store failing). The vectors themselves are replayed by VectorsTest (family `caveat-lang`).
 */
final class CaveatLangTest extends TestCase
{
    private const NOW = 1800000000000;

    private static function j(string $text): Obj
    {
        $v = Json::parseLax($text);
        self::assertInstanceOf(Obj::class, $v);
        return $v;
    }

    private static function ctx(string $params): Obj
    {
        return self::j('{"now":' . self::NOW . ',"action":{"verb":"pay","resource":"r/1","params":' . $params . '}}');
    }

    public function testHostileInputsNeverThrow(): void
    {
        foreach ([null, 1, 'x', [], [1], new Obj(), true, 1.5, new Num('1e300')] as $v) {
            $this->assertFalse(CaveatLang::verifyDischarge($v, $v, $v)['ok']);
            $this->assertFalse(CaveatLang::verifyNarrow($v, $v, $v, $v)['ok']);
            $this->assertFalse(CaveatLang::evaluateK1($v, $v, $v, $v)['ok']);
            $this->assertFalse(CaveatLang::reserveMaxUses(new MemoryStateStore(), $v, $v)['ok']);
            $this->assertNotNull(CaveatLang::needsDischargeError($v));
            $this->assertNotNull(CaveatLang::dischargeShapeError($v));
            $this->assertNotNull(CaveatLang::narrowShapeError($v));
            $this->assertNotNull(CaveatLang::maxUsesError($v));
            $this->assertNotNull(CaveatLang::deriveError($v));
            $this->assertNotNull(CaveatLang::spiffeBoundError($v));
            $this->assertNotNull(CaveatLang::spiffeIdError($v));
            $this->assertNull(CaveatLang::boundCaveats($v, $v));
            $this->assertFalse(CaveatLang::evaluateCaveatsK1($v, $v, $v, $v)[0]);
        }
    }

    public function testSafeIntegerRules(): void
    {
        $mk = static fn(string $n, string $until = '1800000000000'): Obj => self::j('{"type":"max_uses","id":"u","n":' . $n . ',"until":' . $until . '}');
        $this->assertNull(CaveatLang::maxUsesError($mk('2')));
        $this->assertNull(CaveatLang::maxUsesError($mk('2.0')));
        $this->assertNotNull(CaveatLang::maxUsesError($mk('2.5')));
        $this->assertNotNull(CaveatLang::maxUsesError($mk('1e300')));
        $this->assertNotNull(CaveatLang::maxUsesError($mk('257')));
        $this->assertNotNull(CaveatLang::maxUsesError($mk('true')));
        $this->assertNotNull(CaveatLang::maxUsesError($mk('"2"')));
        $this->assertNotNull(CaveatLang::maxUsesError($mk('1', '-0')));
        $this->assertNotNull(CaveatLang::maxUsesError(self::j('{"type":"max_uses","id":"u\n","n":1,"until":1}')));
    }

    public function testSealedFailsOnlyBelowItsHop(): void
    {
        $hop0 = self::j('{"holder":"a","caveats":[{"type":"sealed"}]}');
        $hop1 = self::j('{"holder":"b","caveats":[{"type":"sealed"},{"type":"note"}]}');
        $ctx = self::ctx('{}');
        $this->assertTrue(CaveatLang::evaluateK1($hop0, [$hop0], new Obj(), $ctx)['ok']);
        $r = CaveatLang::evaluateK1($hop0, [$hop0, $hop1], new Obj(), $ctx);
        $this->assertSame(['sealed'], $r['failed']);
        $this->assertSame(['a hop was appended below a sealed hop'], $r['reasons']);
    }

    public function testDeriveIsExactlyTrueOrRefused(): void
    {
        $g = self::j('{"caveats":[{"type":"derive","id":"d1","defs":[{"name":"amt","kind":"param","path":"amount"}],'
            . '"check":{"op":"lte","a":{"ref":"amt"},"b":{"const":100}}}]}');
        $this->assertTrue(CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{"amount":50}'))['ok']);
        $over = CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{"amount":150}'));
        $this->assertSame(['derive'], $over['failed']);
        $this->assertSame(['derive check is false'], $over['reasons']);
        $missing = CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{}'));
        $this->assertSame(['derive check is unknown (a fact is missing)'], $missing['reasons']);
        $str = CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{"amount":"50"}'));
        $this->assertSame(['derive check is unknown (a fact is missing)'], $str['reasons'], 'ordering never coerces a string');
    }

    public function testKleeneOrIsTrueDespiteAnUnknownArm(): void
    {
        $g = self::j('{"caveats":[{"type":"derive","id":"d1","defs":[{"name":"amt","kind":"param","path":"amount"}],'
            . '"check":{"op":"or","args":[{"op":"lte","a":{"ref":"amt"},"b":{"const":1}},{"op":"eq","a":{"const":1},"b":{"const":1}}]}}]}');
        $this->assertTrue(CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{}'))['ok']);
    }

    public function testEqualityNeverCoerces(): void
    {
        $g = self::j('{"caveats":[{"type":"derive","id":"d1","defs":[],"check":{"op":"eq","a":{"const":1},"b":{"const":true}}}]}');
        $this->assertFalse(CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{}'))['ok']);
    }

    public function testSpiffePrefixIsSegmentBounded(): void
    {
        $g = self::j('{"caveats":[{"type":"spiffe_bound","spiffe_prefix":"spiffe://a.test/ns"}]}');
        $k = static fn(string $id): Obj => self::j('{"spiffe_id":"' . $id . '"}');
        $this->assertTrue(CaveatLang::evaluateK1($g, null, $k('spiffe://a.test/ns'), self::ctx('{}'))['ok']);
        $this->assertTrue(CaveatLang::evaluateK1($g, null, $k('spiffe://a.test/ns/x'), self::ctx('{}'))['ok']);
        $this->assertFalse(CaveatLang::evaluateK1($g, null, $k('spiffe://a.test/nsx'), self::ctx('{}'))['ok']);
        $this->assertFalse(CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{}'))['ok']);
    }

    public function testDuplicateIdsFailEveryCaveatSharingThem(): void
    {
        $g = self::j('{"caveats":[{"type":"max_uses","id":"u","n":1,"until":1900000000000},{"type":"max_uses","id":"u","n":2,"until":1900000000000}]}');
        $this->assertSame(['max_uses', 'max_uses'], CaveatLang::evaluateK1($g, null, new Obj(), self::ctx('{}'))['failed']);
    }

    public function testUnknownTypesStayRefusedNextToK1Caveats(): void
    {
        $g = self::j('{"caveats":[{"type":"sealed"},{"type":"future_caveat"}]}');
        $this->assertSame([false, ['future_caveat']], CaveatLang::evaluateCaveatsK1($g, null, new Obj(), self::ctx('{}')));
    }

    public function testReserveSpendsInOrderAndFailsClosedOnAStoreError(): void
    {
        $cap = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE';
        $bound = [['caveat' => self::j('{"type":"max_uses","id":"u","n":1,"until":1900000000000}'), 'cap_hash' => $cap]];
        $store = new MemoryStateStore();
        $this->assertSame(['ok' => true, 'spent' => 1], CaveatLang::reserveMaxUses($store, $bound, self::NOW));
        $this->assertFalse(CaveatLang::reserveMaxUses($store, $bound, self::NOW)['ok']);
        $broken = new class {
            public function claim(string $key, int $counter): never
            {
                throw new \RuntimeException('down');
            }
        };
        $r = CaveatLang::reserveMaxUses($broken, $bound, self::NOW);
        $this->assertFalse($r['ok']);
        $this->assertStringContainsString('fail closed', $r['reason']);
        $this->assertNotSame(CaveatLang::maxUsesSlotKey($cap, 'u', 0), CaveatLang::maxUsesSlotKey($cap, 'u', 1));
    }

    public function testTheVerifierOwnActionDigestReplacesTheCallers(): void
    {
        $o = CaveatLang::withActionDigest(['action_digest' => 'forged', 'pins' => []], 'mine');
        $this->assertSame('mine', $o->get('action_digest'));
        $this->assertSame([], $o->get('pins'));
        $this->assertSame('mine', CaveatLang::withActionDigest('junk', 'mine')->get('action_digest'));
    }

    public function testAbsentK1RefusesEveryK1Type(): void
    {
        $g = self::j('{"caveats":[{"type":"sealed"},{"type":"max_uses","id":"u","n":1,"until":1900000000000},'
            . '{"type":"derive","id":"d","defs":[],"check":{"op":"eq","a":{"const":1},"b":{"const":1}}},'
            . '{"type":"spiffe_bound","spiffe_prefix":"spiffe://a.test"},'
            . '{"type":"needs_discharge","id":"n","issuer":"i","ttl_ms":1000,"require":[]}]}');
        foreach ([null, 'x', 1, [1], true] as $absent) {
            $r = CaveatLang::evaluateK1($g, null, $absent, self::ctx('{}'));
            $this->assertFalse($r['ok']);
            $this->assertCount(5, $r['failed']);
            $this->assertSame(['the caveat language is not configured (no k1 input)'], array_values(array_unique($r['reasons'])));
            $this->assertCount(5, $r['bound']);
        }
        $lone = self::j('{"caveats":[{"type":"sealed"}]}');
        $this->assertSame([false, ['sealed']], CaveatLang::evaluateCaveatsK1($lone, null, null, self::ctx('{}')));
        $this->assertTrue(CaveatLang::evaluateK1($lone, null, new Obj(), self::ctx('{}'))['ok'], 'an empty present object is configured');
        $this->assertTrue(CaveatLang::evaluateK1($lone, null, [], self::ctx('{}'))['ok']);
    }

    public function testConsumeOnceTtlOnBothStores(): void
    {
        $pdo = new PdoStateStore(new \PDO('sqlite::memory:'));
        $pdo->createTable();
        foreach ([new MemoryStateStore(), $pdo] as $s) {
            $this->assertTrue($s->consumeOnce('k', 20, 10));
            $this->assertFalse($s->consumeOnce('k', 20, 20), 'now == retain_until is live');
            $this->assertFalse($s->consumeOnce('k', 40, 20));
            $this->assertFalse($s->consumeOnce('k', 50, 30), 'the longer horizon of the live repeat was kept');
            $this->assertTrue($s->consumeOnce('k', 90, 51));
            foreach ([['', 20, 10], ['z', 9, 10]] as [$k, $u, $n]) {
                try {
                    $s->consumeOnce($k, $u, $n);
                    $this->fail('must refuse');
                } catch (\InvalidArgumentException) {
                    $this->assertTrue($s->consumeOnce($k === '' ? 'q' : $k, 100, 10), 'a refused call leaves nothing behind');
                }
            }
        }
    }

    public function testReserveKeepsTheSlotUntilTheCaveatExpires(): void
    {
        $cap = 'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE';
        $until = self::NOW + 1000;
        $bound = [['caveat' => self::j('{"type":"max_uses","id":"u","n":1,"until":' . $until . '}'), 'cap_hash' => $cap]];
        $store = new MemoryStateStore();
        $this->assertTrue(CaveatLang::reserveMaxUses($store, $bound, self::NOW)['ok']);
        $slot = CaveatLang::maxUsesSlotKey($cap, 'u', 0);
        $this->assertFalse($store->consumeOnce($slot, $until, $until), 'still remembered at until');
        $this->assertTrue($store->consumeOnce($slot, $until + 5, $until + 1), 'forgotten after until');
    }

    public function testPresentedK1Headers(): void
    {
        $b = static fn(string $t): string => Pca::b64u($t);
        $r = CaveatLang::presentedK1(['PCA-Discharges' => $b('[{"a":1}]'), 'pca-narrow' => $b('{"v":1}')]);
        $this->assertTrue($r['ok']);
        $this->assertCount(1, $r['value']->get('discharges'));
        $this->assertTrue($r['value']->has('narrow'));
        $this->assertSame([], $r['value']->keys() === [] ? [] : array_diff($r['value']->keys(), ['discharges', 'narrow']));
        $this->assertFalse(CaveatLang::presentedK1(['pca-discharges' => $b('{"a":1}')])['ok']);
        $this->assertFalse(CaveatLang::presentedK1(['pca-narrow' => $b('{"a":1,"a":2}')])['ok']);
        $this->assertSame([], CaveatLang::presentedK1(['pca-narrow' => ''])['value']->keys());
        foreach ([null, 1, 'x', [1]] as $h) {
            $this->assertTrue(CaveatLang::presentedK1($h)['ok']);
        }
        $own = CaveatLang::mergePresentedK1(['pca-discharges' => $b('[1]')], ['discharges' => [2], 'pins' => []]);
        $this->assertSame([2], $own->get('discharges'), 'own members win');
        $this->assertSame([], CaveatLang::mergePresentedK1(['pca-discharges' => '!!'], new Obj())->keys());
    }

    public function testMiddlewareMergesPresentedHeadersOnlyWhenK1IsConfigured(): void
    {
        $call = static function (?AuthorizeOptions $o, ServerRequest $req): mixed {
            $m = (new \ReflectionClass(PcaMiddleware::class))->newInstanceWithoutConstructor();
            $f = new \ReflectionMethod($m, 'k1Of');
            return $f->invoke($m, $req, new Obj(), $o);
        };
        $req = new ServerRequest('GET', '/', ['PCA-Discharges' => Pca::b64u('[{"x":1}]')]);
        $this->assertNull($call(new AuthorizeOptions(), $req));
        $k = $call(new AuthorizeOptions(k1: new Obj()), $req);
        $this->assertCount(1, $k->get('discharges'));
        $this->assertFalse($call(new AuthorizeOptions(k1: new Obj()), new ServerRequest('GET', '/'))->has('discharges'));
        $this->assertSame('mine', $call(new AuthorizeOptions(k1: static fn() => ['narrow' => 'mine']), $req)->get('narrow'));
        $this->assertFalse($call(new AuthorizeOptions(k1: new Obj()), new ServerRequest('GET', '/', ['PCA-Discharges' => '!!']))->has('discharges'));
    }
}
