<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Dataflow.php';

use Atlas\Pca\Dataflow;
use Atlas\Pca\FlowCapability;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Tagged;
use Atlas\Pca\TraceRuleError;
use PHPUnit\Framework\TestCase;

/** A class name whose static sinkFor would resolve a sink: a class-name string is still not a resolver. */
final class G21StaticSinkPolicy
{
    public static function sinkFor(mixed $action): Obj
    {
        return Dataflow::externalSendSink('k');
    }
}

/** Data flow: tagged values and sets, sink checks and resolvers, trace rules and their lowering, the trifecta lint, detector policy and receipts. */
final class GrantSurvivorKill21DataflowTest extends TestCase
{
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

    // ---- tagged values, sets, sinks -----------------------------------------------------------------------------------

    /** Only the module mints a Tagged; derive refuses anything else with its own message. */
    public function testTaggedConstruction(): void
    {
        $this->assertThrown(\TypeError::class, 'a Tagged value is made by tag(), fromTrustedQuery(), fromToolOutput(), fromSource() or derive()',
            fn() => new Tagged(1, new FlowCapability([], false)));
        $t = Dataflow::fromSource('s', 1);
        $this->assertTrue(Dataflow::isTagged($t));
        $this->assertFalse($t->cap->isTrusted, 'a source is untrusted unless vouched for');
        $msg = 'derive: every input must be a tagged value made by this module';
        $this->assertThrown(\TypeError::class, $msg, fn() => Dataflow::derive('x', static fn() => 1));
        $this->assertThrown(\TypeError::class, $msg, fn() => Dataflow::derive([1], static fn() => 1));
    }

    /** Set membership is by type and value: '1' and 1, two different objects, NaN and Infinity are all distinct. */
    public function testSetKeys(): void
    {
        $this->assertCount(2, Dataflow::toSet(['1', 1]));
        $this->assertCount(2, Dataflow::toSet([Obj::of(['a' => 1]), Obj::of(['b' => 1])]));
        $this->assertCount(2, Dataflow::toSet([NAN, INF]));
        $this->assertCount(1, Dataflow::toSet([Obj::of(['a' => 1]), Obj::of(['a' => 1])]));
    }

    /** Sink checks: a non-list source list is a TypeError, paths are lists, sources print as JS strings; the sensitive sink is exact. */
    public function testClassifyFlow(): void
    {
        $t = Dataflow::tag(1, new FlowCapability(['a', 'b'], false));
        $this->assertThrown(\TypeError::class, 'has is not a function',
            fn() => Dataflow::classifyFlow($t, Obj::of(['id' => 'k', 'accepts' => Obj::of(['denied_sources' => 'x'])])));
        $d = Dataflow::classifyFlow($t, Obj::of(['id' => 'k', 'accepts' => Obj::of(['denied_sources' => ['b']])]));
        $this->assertSame(["provenance [b] is forbidden at sink 'k'", ['b']], [$d->get('reason'), $d->get('path')]);
        $d = Dataflow::classifyFlow($t, Obj::of(['id' => 'k', 'accepts' => Obj::of(['allowed_sources' => ['a']])]));
        $this->assertSame(["provenance [b] is not in the allow-list of sink 'k'", ['b']], [$d->get('reason'), $d->get('path')]);
        $odd = Dataflow::tag(1, new FlowCapability([true], false));
        $this->assertSame("untrusted value (provenance [true]) may not flow to external-send sink 'k' — exfiltration / prompt-injection path",
            Dataflow::classifyFlow($odd, Dataflow::externalSendSink('k'))->get('reason'));
        $this->assertSame('{"id":"k","accepts":{"require_trusted":true}}', Js::stringify(Dataflow::sensitiveSink('k')));
    }

    /** The resolver is a Closure or an object's sinkFor; anything else (an invokable without sinkFor still counts, a class name does not) fails closed. */
    public function testCheckActionResolvers(): void
    {
        $t = Dataflow::fromTrustedQuery(1);
        $allow = ['outcome' => 'allow', 'sink' => 'k'];
        $sink = Dataflow::externalSendSink('k');
        $obj = new class ($sink) {
            public function __construct(private Obj $s)
            {
            }

            public function sinkFor(mixed $a): Obj
            {
                return $this->s;
            }
        };
        $invokable = new class ($sink) {
            public function __construct(private Obj $s)
            {
            }

            public function __invoke(mixed $a): Obj
            {
                return $this->s;
            }
        };
        foreach ([static fn($a) => $sink, $obj, $invokable] as $policy) {
            $this->assertSame(Js::stringify(Obj::of($allow)), Js::stringify(Dataflow::checkAction('send', [$t], $policy)));
        }
        $this->assertSame('{"outcome":"deny","sink":"(unresolved)","reason":"the sink for this action could not be resolved (fail closed)"}',
            Js::stringify(Dataflow::checkAction('send', [$t], G21StaticSinkPolicy::class)));
    }

    // ---- trace rules --------------------------------------------------------------------------------------------------

    private static function table(array $verbs): Obj
    {
        $o = new Obj();
        foreach ($verbs as $v => $traits) {
            $o->set((string)$v, Obj::of(['traits' => $traits]));
        }
        return $o;
    }

    private function traceError(callable $f): TraceRuleError
    {
        try {
            $f();
        } catch (TraceRuleError $e) {
            return $e;
        }
        $this->fail('expected a TraceRuleError');
    }

    /** Selector parsing: `trait:` needs a 1..256 character id after the colon; a single character is fine. */
    public function testTraitSelectorBounds(): void
    {
        $e = $this->traceError(fn() => Dataflow::parseTraceRule('r', 'never trait: after tool:a within 1m'));
        $this->assertSame(['selector', "'trait:' is not tool:<verb>, trait:<id>, resource:<prefix> or any"], [$e->errorCode, $e->getMessage()]);
        $this->assertSame(['a'], Dataflow::parseTraceRule('r', 'never trait:a after tool:a within 1m')->get('never')->get('traits'));
        $long = str_repeat('x', 256);
        $this->assertSame([$long], Dataflow::parseTraceRule('r', "never trait:$long after tool:a within 1m")->get('never')->get('traits'));
    }

    /** Invariant import: text must be a string; an unsupported line is refused unless dropUnsupported is passed. */
    public function testInvariantImport(): void
    {
        $this->assertThrown(\TypeError::class, 'text.split is not a function', fn() => Dataflow::parseInvariantRule('r', 5, '1m'));
        $text = "raise \"m\" if:\n(x: ToolCall) -> (y: ToolCall)\nfoo bar";
        $e = $this->traceError(fn() => Dataflow::parseInvariantRule('r', $text, '1m'));
        $this->assertSame(['unsupported', "'foo bar' is outside the compilable subset (x is tool:<name>); pass dropUnsupported to refuse more instead"],
            [$e->errorCode, $e->getMessage()]);
        $this->assertSame(['foo bar'], Dataflow::parseInvariantRule('r', $text, '1m', true)->get('dropped'));
    }

    /** Lowering: windows 1 ms and 30 days are allowed (edges keep the integer), 8 B verbs fit one caveat, 64 caveats are allowed and 65 are not. */
    public function testCompileTraceRules(): void
    {
        $t = self::table(['a' => [], 'b' => []]);
        foreach (['1ms' => 1, '30d' => 2592000000] as $w => $ms) {
            $out = Dataflow::compileTraceRules([Dataflow::parseTraceRule('r', "never tool:b after tool:a within $w")], $t);
            $this->assertSame($ms, $out->get('edges')[0]->get('within_ms'));
        }
        $eight = ['a' => []];
        for ($i = 1; $i <= 8; $i++) {
            $eight["b$i"] = ['tb'];
        }
        $this->assertCount(1, Dataflow::compileTraceRules([Dataflow::parseTraceRule('r', 'never trait:tb after tool:a within 1m')], self::table($eight))->get('caveats'));
        $many = static function (int $n): Obj {
            $v = ['z' => []];
            for ($i = 0; $i < $n; $i++) {
                $v[sprintf('a%02d', $i)] = ['ta'];
            }
            return self::table($v);
        };
        $rule = Dataflow::parseTraceRule('r', 'never tool:z after trait:ta within 1m');
        $this->assertCount(64, Dataflow::compileTraceRules([$rule], $many(64))->get('caveats'));
        $e = $this->traceError(fn() => Dataflow::compileTraceRules([$rule], $many(65)));
        $this->assertSame(['too_large', 'more than 64 caveats: split the rule set or narrow the selectors'], [$e->errorCode, $e->getMessage()]);
        $e = $this->traceError(fn() => Dataflow::compileTraceRules([Dataflow::parseTraceRule('r', 'never trait:zz after tool:a within 1m')], $t));
        $this->assertSame(['empty_selector', "rule 'r' never: trait 'zz' matches no action"], [$e->errorCode, $e->getMessage()]);
        // a trait can reach a verb longer than the 256-byte constant bound: the lowered caveat is invalid and refused, never emitted
        $e = $this->traceError(fn() => Dataflow::compileTraceRules([Dataflow::parseTraceRule('r', 'never trait:tl after tool:a within 1m')],
            self::table(['a' => [], str_repeat('v', 257) => ['tl']])));
        $this->assertSame('internal', $e->errorCode);
        $this->assertStringStartsWith("rule 'r' compiled to an invalid caveat: ", $e->getMessage());
    }

    /** Malformed rule lists and tables are TypeErrors with the reference's messages. */
    public function testCompileTraceRulesTypeErrors(): void
    {
        $t = self::table(['a' => [], 'b' => []]);
        $this->assertThrown(\TypeError::class, "cannot read 'id'", fn() => Dataflow::compileTraceRules([5], $t));
        $this->assertThrown(\TypeError::class, "cannot read 'id'", fn() => Dataflow::compileTraceRules([Obj::of([])], $t));
        $this->assertThrown(\TypeError::class, 'table is not an object',
            fn() => Dataflow::compileTraceRules([Dataflow::parseTraceRule('r', 'never tool:b after tool:a within 1m')], 5));
        $this->assertThrown(\TypeError::class, 'table is not an object', fn() => Dataflow::lethalTrifecta(5, []));
    }

    // ---- lethal trifecta ----------------------------------------------------------------------------------------------

    private static function lethalTable(array $priv, array $untr): Obj
    {
        $o = new Obj();
        foreach ($priv as $p) {
            $o->set($p, Obj::of(['traits' => ['pca.pii_access']]));
        }
        foreach ($untr as $u) {
            $o->set($u, Obj::of(['traits' => []]));
        }
        $o->set('s', Obj::of(['traits' => ['pca.external_communication']]));
        return $o;
    }

    private static function edge(string $from, string $to): Obj
    {
        return Obj::of(['from' => Obj::of(['tool' => $from]), 'to' => $to]);
    }

    /** Edges are only read when all three legs exist; a non-object `from` is no rule; finding lists are filtered lists. */
    public function testLethalTrifecta(): void
    {
        $r = Dataflow::lethalTrifecta(self::lethalTable([], ['u']), [5], ['u']);
        $this->assertSame([[], ['u'], ['s'], []], [$r->get('private_reads'), $r->get('untrusted_reads'), $r->get('sends'), $r->get('findings')]);
        $f = Dataflow::lethalTrifecta(self::lethalTable(['p'], ['u']), [Obj::of(['from' => 'x', 'to' => 's'])], ['u'])->get('findings');
        $this->assertSame([['s'], ['u'], ['p']], [[$f[0]->get('send')], $f[0]->get('from_untrusted'), $f[0]->get('from_private')]);
        $f = Dataflow::lethalTrifecta(self::lethalTable(['p1', 'p2'], ['u1', 'u2']), [self::edge('u1', 's'), self::edge('p1', 's')], ['u1', 'u2'])->get('findings');
        $this->assertSame([['u2'], ['p2']], [$f[0]->get('from_untrusted'), $f[0]->get('from_private')]);
        $this->assertSame([], Dataflow::lethalTrifecta(self::lethalTable(['p'], ['u']), [self::edge('u', 's')], ['u'])->get('findings'));
    }

    // ---- detector policy and receipts ---------------------------------------------------------------------------------

    private static function gw(): KeyPair
    {
        return new KeyPair(str_repeat("\4", 32));
    }

    private static function det(string $id = 'lakera', array $over = []): Obj
    {
        return Obj::of($over + ['id' => $id, 'keys' => [Obj::of(['pk' => self::gw()->public])], 'on_suspicious' => 'deny', 'max_age_ms' => new Num('60000')]);
    }

    private static function policy(Obj ...$d): Obj
    {
        return Obj::of(['detectors' => $d === [] ? [self::det()] : $d]);
    }

    /** Every policy bound and shape check, exactly. */
    public function testDetectorPolicyShape(): void
    {
        $this->assertSame('policy must be {detectors}', Dataflow::detectorPolicyError(5));
        $sixteen = [];
        for ($i = 0; $i < 16; $i++) {
            $sixteen[] = self::det("d$i");
        }
        $this->assertNull(Dataflow::detectorPolicyError(Obj::of(['detectors' => $sixteen])));
        foreach ([['a' => self::det()], 5] as $ds) {
            $this->assertSame('detectors must hold at most 16 entries', Dataflow::detectorPolicyError(Obj::of(['detectors' => $ds])));
        }
        foreach ([5, self::det('lakera', ['x' => 1])] as $d) {
            $this->assertSame('detector entry is malformed', Dataflow::detectorPolicyError(Obj::of(['detectors' => [$d]])));
        }
        $pins = "detector 'lakera': keys must hold 1..8 pins";
        $this->assertNull(Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['keys' => array_fill(0, 8, Obj::of(['pk' => 'x']))]))));
        $this->assertNull(Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['keys' => [Obj::of(['pk' => 'x', 'pq_pk' => 'y'])]]))));
        foreach ([['a' => Obj::of(['pk' => 'x'])], [5], [Obj::of(['pk' => 5])], [Obj::of(['pk' => 'x', 'pq_pk' => 5])]] as $keys) {
            $this->assertSame($pins, Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['keys' => $keys]))), (string)json_encode(array_keys($keys)));
        }
        $cats = "detector 'lakera': categories must be 1+ ids";
        $this->assertNull(Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['categories' => ['ok']]))));
        $this->assertSame($cats, Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['categories' => 'x']))));
        $this->assertSame($cats, Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['categories' => ['BAD']]))));
        foreach (['1', '86400000'] as $age) {
            $this->assertNull(Dataflow::detectorPolicyError(self::policy(self::det('lakera', ['max_age_ms' => new Num($age)]))));
        }
    }

    private static function receipt(string $verdict, array $over = [], array $cats = []): Obj
    {
        $b = Obj::of($over + ['v' => new Num('1'), 'kind' => 'pca-detector-receipt', 'detector' => 'lakera', 'version' => '1',
            'input_digest' => Dataflow::detectorInputDigest('hello'), 'verdict' => $verdict, 'categories' => $cats, 'iat' => new Num('1000')]);
        return Dataflow::signDetectorReceipt($b, self::gw());
    }

    private static function fold(array $receipts, ?Obj $policy = null, int $now = 2000, mixed $session = null): array
    {
        $in = ['receipts' => $receipts, 'policy' => $policy ?? self::policy(), 'input_digests' => [Dataflow::detectorInputDigest('hello')], 'now' => $now];
        return Dataflow::detectorSignal($session === null ? $in : $in + ['session' => $session]);
    }

    private static function sus(string $detector = 'lakera', array $cats = []): Obj
    {
        return self::receipt('suspicious', ['detector' => $detector], $cats);
    }

    /** A malformed policy or receipt list gives its exact result; the env always carries every detector and the invalid count. */
    public function testSignalExactShapes(): void
    {
        $r = Dataflow::detectorSignal(['policy' => 5, 'now' => 1]);
        $this->assertSame(['deny', '{"detect":{"invalid":0}}', [], [['index' => -1, 'reason' => 'policy: policy must be {detectors}']]],
            [$r['signal'], Js::stringify($r['env']), $r['flagged'], $r['rejected']]);
        $r = self::fold(['a' => self::receipt('no_finding')]);
        $this->assertSame(['escalate', '{"detect":{"lakera":false,"invalid":1}}', [['index' => -1, 'reason' => 'receipt list or clock malformed']]],
            [$r['signal'], Js::stringify($r['env']), $r['rejected']]);
        $r = self::fold(array_fill(0, 32, self::receipt('no_finding')));
        $this->assertSame(['ok', '{"detect":{"lakera":false,"invalid":0}}', []], [$r['signal'], Js::stringify($r['env']), $r['rejected']]);
        $other = self::receipt('no_finding', ['input_digest' => Dataflow::detectorInputDigest('other')]);
        $this->assertSame([['index' => 0, 'reason' => "detector 'lakera': the receipt is about other content"]], self::fold([$other])['rejected']);
    }

    /** Session binding, the clock edge (iat == now) and the age edge (now - iat == max_age_ms) are all accepted. */
    public function testReceiptTimeAndSession(): void
    {
        $sid = Pca::b64u(str_repeat("\7", 32));
        $this->assertSame([], self::fold([self::receipt('no_finding')], null, 2000, $sid)['rejected'], 'an unbound receipt fits any session');
        $this->assertSame([], self::fold([self::receipt('no_finding', ['session' => $sid])], null, 2000, $sid)['rejected']);
        $this->assertSame([], self::fold([self::receipt('no_finding')], null, 1000)['rejected']);
        $this->assertSame([], self::fold([self::receipt('no_finding')], null, 61000)['rejected']);
    }

    /** Folding: deny beats an earlier escalate; a rejected or no_finding receipt does not end the scan; each receipt acts for its own detector; flagged is sorted. */
    public function testFold(): void
    {
        $bad = self::receipt('no_finding', ['input_digest' => Dataflow::detectorInputDigest('other')]);
        $r = self::fold([$bad, self::sus()]);
        $this->assertSame(['deny', ['lakera']], [$r['signal'], $r['flagged']]);
        $this->assertSame(['lakera'], self::fold([self::receipt('no_finding'), self::sus()])['flagged']);
        $two = self::policy(self::det('bbb', ['on_suspicious' => 'deny']), self::det('aaa', ['on_suspicious' => 'escalate']));
        $r = self::fold([self::sus('aaa')], $two);
        $this->assertSame(['escalate', ['aaa']], [$r['signal'], $r['flagged']]);
        $r = self::fold([self::sus('bbb')], $two);
        $this->assertSame(['deny', ['bbb']], [$r['signal'], $r['flagged']]);
        $r = self::fold([self::sus('bbb')], self::policy(self::det('aaa', ['on_suspicious' => 'escalate']), self::det('bbb')));
        $this->assertSame(['deny', ['bbb']], [$r['signal'], $r['flagged']]);
        $this->assertSame(['aaa', 'bbb'], self::fold([self::sus('bbb'), self::sus('aaa')], $two)['flagged']);
        $catd = self::policy(self::det('lakera', ['categories' => ['injection']]));
        $this->assertSame(['lakera'], self::fold([self::sus('lakera', [])], $catd)['flagged'], 'a receipt without categories always acts');
        $this->assertSame(['lakera'], self::fold([self::sus('lakera', ['pii']), self::sus('lakera', ['injection'])], $catd)['flagged']);
    }

    /** Signing: a seed or a KeyPair; a non-string key is the seed-length error; an explicit ed25519 keeps a written alg; a PQ suite needs its key pair. */
    public function testSignDetectorReceipt(): void
    {
        $body = Obj::of(['v' => new Num('1'), 'kind' => 'pca-detector-receipt', 'detector' => 'lakera', 'version' => '1',
            'input_digest' => Dataflow::detectorInputDigest('hello'), 'verdict' => 'no_finding', 'categories' => [], 'iat' => new Num('1000')]);
        $this->assertSame(Js::stringify(Dataflow::signDetectorReceipt($body, self::gw())), Js::stringify(Dataflow::signDetectorReceipt($body, str_repeat("\4", 32))));
        $this->assertThrown(\InvalidArgumentException::class, 'an Ed25519 seed is 32 bytes', fn() => Dataflow::signDetectorReceipt($body, 5));
        $withAlg = Obj::of(['alg' => 'ed25519']);
        foreach ($body->keys() as $k) {
            $withAlg->set($k, $body->get($k));
        }
        $this->assertSame('ed25519', Dataflow::signDetectorReceipt($withAlg, self::gw(), 'ed25519')->get('alg'));
        $this->assertThrown(\InvalidArgumentException::class, 'ml-dsa-65 needs a post-quantum key pair', fn() => Dataflow::signDetectorReceipt($body, self::gw(), 'ml-dsa-65'));
    }

    /** Category ids lowercase as Unicode (KELVIN SIGN becomes k). */
    public function testCategoryIdUnicodeLowercase(): void
    {
        $this->assertSame('kill', Dataflow::categoryId("\u{212A}ill"));
    }
}
