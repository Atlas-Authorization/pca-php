<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/IntentV2.php (decideIntentV2 pipeline, verifyRegistrySig): which schema document / claim a
 * lookup picks (the FIRST match, like the reference's `find`), the accumulator step's context-error order, the ceiling
 * layers feeding the model-path scan, the W-B single_source handed to rule 21, rule 20's verb lookup and the host env merged
 * into rule 21. Signed fixtures are IntentV2KillTest's / IntentWbKillTest's own (called through reflection).
 */
final class K05KillIntentV2PipelineTest extends TestCase
{
    private const RISK = '"risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,'
        . '"kappa":1,"lambda":0,"rho":0,"bMax":0}';

    private static function kt(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentV2KillTest::class, $m))->invokeArgs(null, $a);
    }

    private static function wb(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentWbKillTest::class, $m))->invokeArgs(null, $a);
    }

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    /** A grant whose envelope (readable by Authorize::readEnvelope) carries `$extra` members (DecisionTest's shape). */
    private static function envGrant(string $predicates = '[{"verb":"*","where":[]}]', string $extra = ''): Obj
    {
        return self::j('{"id":"g1","caveats":[{"type":"envelope","goal_commit":"x","predicates":' . $predicates . ',"caveats":[],'
            . '"agent_binding":{},' . self::RISK . $extra . '}]}');
    }

    /** @return array<string,true|string> check name => true | reason */
    private static function checks(array $d): array
    {
        $out = [];
        foreach ($d['checks'] as $c) {
            $out[$c['name']] = $c['ok'] ? true : $c['reason'];
        }
        return $out;
    }

    public function testRegistrySigInternalErrorCarriesItsMessage(): void
    {
        $key = self::o(['kid' => 'k', 'pk' => str_repeat('A', 43)]);
        $this->assertSame(['ok' => false, 'reason' => 'verification error: canonicalize: non-finite number'],
            IntentV2::verifyRegistrySig('d', Obj::of(['x' => NAN]), self::o(['kid' => 'k']), [$key]));
    }

    public function testSchemaStepPicksTheFirstDocumentWithTheDigest(): void
    {
        // two documents with one strict canonical form (one digest) but another member order: the first one is used
        $d1 = self::j('{"x":1,"y":1}');
        $d2 = self::j('{"y":1,"x":1}');
        $this->assertSame(IntentV2::actionSchemaDigest($d1), IntentV2::actionSchemaDigest($d2));
        $p = self::o(['intent_session' => ['schema' => IntentV2::actionSchemaDigest($d1)]]);
        $ctx = Obj::of(['schema' => Obj::of(['docs' => [$d1, $d2], 'keys' => []])]);
        $c = self::checks(IntentV2::decideIntentV2($p, null, $ctx, 0));
        $this->assertSame("schema does not verify: unknown member 'x'", $c['schema']);
    }

    public function testAccumulatorStepReportsTheAccContextBeforeTheSchemaContext(): void
    {
        [$g, $p] = self::kt('base');
        $r = self::kt('v2', $p, $g, self::kt('ctx', ['acc' => ['state' => 5], 'schema' => new \stdClass()]));
        $this->assertSame('acc.state must be an object', $r['accumulators']);
    }

    public function testAccumulatorStepUsesTheFirstClaimOfAnId(): void
    {
        $g = self::kt('grant');
        $is = self::kt('intentSession', ['acc' => [['id' => 'trip_spend', 'post' => 38900], ['id' => 'trip_spend', 'post' => 1]]]);
        $p = self::kt('pcactn', $g, $is);
        $this->assertTrue(self::kt('v2', $p, $g, self::kt('ctx'))['accumulators']);
    }

    public function testUnitsRuleReadsTheActionVerbsEntry(): void
    {
        // air.book (the action verb) is the SECOND verb: its total is declared in usd_cents, the envelope tags it a count
        $verbs = array_reverse(self::kt('unsignedSchema')['verbs']);
        $doc = self::kt('schema', ['verbs' => $verbs]);
        $g = self::kt('grant');
        $p = self::kt('pcactn', $g, self::kt('intentSession', ['schema' => IntentV2::actionSchemaDigest($doc)]));
        $env = $g->get('caveats')[0];
        $env->set('predicates', self::j('[{"verb":"*","where":[]}]'));
        $env->set('caveats', []);
        $env->set('agent_binding', self::j('{}'));
        $env->set('risk_policy', self::j('{' . self::RISK . '}')->get('risk_policy'));
        $env->set('units', self::j('{"action.params.total":{"kind":"count"}}'));
        $r = self::kt('v2', $p, $g, self::kt('ctx', ['schema' => ['docs' => [$doc], 'keys' => self::kt('keys')]]));
        $this->assertTrue($r['schema']);
        $this->assertIsString($r['units']);
        $this->assertStringStartsWith("'action.params.total' is declared as ", $r['units']);
        $this->assertStringEndsWith('(unit confusion)', $r['units']);
    }

    public function testOrgCeilingPredicatesFeedTheModelPathScan(): void
    {
        $ctx = self::j('{"layers":{"org":{"predicates":[{"verb":"*","where":[{"field":"env.judge.score","op":"gt","value":1}]}]}}}');
        $p = self::j('{"aud":"a","action":{"verb":"refund","resource":"r"}}');
        $c = self::checks(IntentV2::decideIntentV2($p, self::envGrant(), $ctx, 1));
        $this->assertSame(['tighten'], array_keys($c));
        $this->assertIsString($c['tighten']);
        $this->assertStringContainsString('env.judge.score', $c['tighten']);
    }

    public function testTightenSeesTheHostEnv(): void
    {
        $g = self::envGrant(extra: ',"tighten":[{"id":"r1","when":{"field":"env.judge.score","op":"gt","value":5},"signal":"escalate"}]');
        $p = self::j('{"aud":"a","action":{"verb":"refund","resource":"r"}}');
        $this->assertTrue(self::checks(IntentV2::decideIntentV2($p, $g, self::j('{"env":{"judge":{"score":1}}}'), 1))['tighten']);
    }

    public function testWbSingleSourceReachesTheTightenRule(): void
    {
        $now = 1800000000000;
        $fact = self::wb('fact', 'o1', 7);
        $world = self::wb('world', 'fare', 1, 0, ['o1']);
        $p = self::o(['aud' => 'skyair.example', 'action' => ['verb' => 'air.book', 'resource' => 'skyair.example/bookings'],
            'intent_session' => ['session' => Pca::b64u(hash('sha256', 'session', true)), 'facts' => [IntentWb::factRef(self::o($fact))]]]);
        $ctx = self::o(['params' => ['offer_id' => 'OF-2'],
            'wb' => ['artifacts' => ['facts' => [$fact]], 'policy' => ['world' => ['worlds' => [$world]]]]]);
        $g = self::envGrant('[{"verb":"*","where":[{"field":"env.world.fare","op":"gt","value":1}]}]');
        $c = self::checks(IntentV2::decideIntentV2($p, $g, $ctx, $now));
        $this->assertTrue($c['facts']);
        $this->assertArrayHasKey('tighten', $c); // env.world.fare is single-source: model-derived only through single_source
        $this->assertIsString($c['tighten']);
        $this->assertStringContainsString('env.world.fare', $c['tighten']);
    }

    protected function tearDown(): void
    {
        IntentV2::$faultHook = null;
    }

    /** The members of an Obj as a PHP assoc array: the same strict canonical form (same digest), but not an Obj. */
    private static function assoc(Obj $o): array
    {
        $a = [];
        foreach ($o->keys() as $k) {
            $a[$k] = $o->get($k);
        }
        return $a;
    }

    public function testVerifyEd25519FailsClosedWhenItsBodyThrows(): void
    {
        IntentV2::$faultHook = static function (string $step): void {
            throw new \RuntimeException("boom:$step");
        };
        $this->assertFalse(IntentV2::verifyEd25519(str_repeat('A', 43), 'm', str_repeat('A', 86)));
    }

    public function testWbErrorFailsTheFactsCheckWithItsMessage(): void
    {
        IntentV2::$faultHook = static function (string $step): void {
            if ($step === 'wb') {
                throw new \RuntimeException('boom');
            }
        };
        $d = IntentV2::decideIntentV2(Obj::of(['intent_session' => new Obj()]), null, new Obj(), 0);
        $facts = array_values(array_filter($d['checks'], static fn(array $c): bool => ($c['name'] ?? null) === 'facts'));
        $this->assertSame([['name' => 'facts', 'ok' => false, 'reason' => 'W-B error (fail closed): boom']], $facts);
    }

    public function testAccumulatorStepPicksTheFirstSchemaDocumentWithTheDigest(): void
    {
        // the twin has the schema's digest but is no Obj: picked, it would select nothing (claim for an unfed accumulator)
        [$g, $p] = self::kt('base');
        $doc = self::kt('schema');
        $twin = self::assoc($doc);
        $this->assertSame(IntentV2::actionSchemaDigest($doc), IntentV2::actionSchemaDigest($twin));
        $ctx = self::kt('ctx');
        $ctx->get('schema')->set('docs', [$doc, $twin]);
        $this->assertTrue(self::kt('v2', $p, $g, $ctx)['accumulators']);
    }

    public function testSequencedAccumulatorPicksTheFirstReceiptWithTheDigest(): void
    {
        $S = self::kt('root', ['accumulators' => [self::kt('trip', ['holder' => ['kind' => 'sequenced', 'uri' => 'https://seq',
            'root' => self::kt('pub', 'seq-root')]])]]);
        $g = self::kt('grant', 0, null, $S);
        $rc = self::kt('receipt', self::kt('pcactn', $g, self::kt('intentSession', [], $S)));
        $is = self::kt('intentSession', ['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => IntentV2::accReceiptDigest($rc)]]], $S);
        $p = self::kt('pcactn', $g, $is);
        $twin = self::assoc($rc);
        $this->assertSame(IntentV2::accReceiptDigest($rc), IntentV2::accReceiptDigest($twin));
        $ctx = self::kt('ctx', ['session' => ['root' => $S, 'grants' => []], 'acc' => ['sequencer_keys' => [self::kt('keySet')]]]);
        $ctx->get('acc')->set('receipts', [$rc, $twin]);
        $this->assertTrue(self::kt('v2', $p, $g, $ctx)['accumulators']);
    }
}
