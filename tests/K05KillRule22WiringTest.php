<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentV2.php';

use Atlas\Pca\ActionsRegistry;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Rule 22 and the grant pin inside decideIntentV2 (intent-v2.ts:321-325, 614-634; expected values from
 * packages/pca-actions/test/verifier.test.ts). Documents are the shared rule 22 vectors, re-signed by a site key here.
 */
final class K05KillRule22WiringTest extends TestCase
{
    private const VERB = 'stripe.refund';
    private const DEF = 'Xo7ApENRzJyi5iakmamfXyLK2S7-jBcDWk2dwARzONE';
    private const CAV = ['amount_cap', 'count_cap', 'window'];
    private const CONTEXT = ['fresh_revocation', 'idempotency'];
    private const ESCALATE = 'escalate: the action floors need a caveat, context or confirmation the grant does not provide (rule 22)';
    private const EXCEED = 'the action floors exceed what the grant authorizes (rule 22)';
    private const RISK = ['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0], 'theta1' => 0, 'theta2' => 1,
        'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'bMax' => 0];

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
    }

    private static function vector(string $name): Obj
    {
        return Json::parseLax((string)file_get_contents(ActionVectors::dir() . "/$name.json"))->get('input');
    }

    private static function kp(): array
    {
        static $k = null;
        return $k ??= (static function (): array {
            $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x07", 32));
            return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
        })();
    }

    private static function keys(): array
    {
        return [self::o(['kid' => 'k1', 'alg' => 'ed25519', 'pk' => self::kp()[0]])];
    }

    private static function signed(string $domain, Obj $body): Obj
    {
        $body->set('sig', self::o(['alg' => 'ed25519', 'kid' => 'k1',
            'value' => Pca::b64u(sodium_crypto_sign_detached($domain . IntentV2::canonicalize($body), self::kp()[1]))]));
        return $body;
    }

    private static function doc(string $vector = 'rule22-conf-allow'): Obj
    {
        $d = self::vector($vector)->get('doc');
        $d->set('pack', self::o(['ns' => 'stripe', 'version' => '1.0.0', 'root' => str_repeat('A', 43)]));
        return self::signed(IntentV2::ACTION_SCHEMA_DOMAIN, $d);
    }

    private static function pin(array $over = []): array
    {
        return array_merge(['pack' => ['ns' => 'stripe', 'root' => str_repeat('A', 43)], 'defs' => [self::VERB => self::DEF], 'on_new_action' => 'deny',
            'max_esc' => 3, 'preauth_esc' => 2, 'caveats' => self::CAV], $over);
    }

    /** A grant whose envelope carries `$extra` members. */
    private static function grant(array $extra = []): Obj
    {
        return self::o(['id' => str_repeat('G', 43), 'issuer' => str_repeat('I', 43), 'caveats' => [array_merge(['type' => 'envelope', 'goal_commit' => 'x',
            'predicates' => [['verb' => '*', 'where' => []]], 'caveats' => [], 'agent_binding' => new \stdClass(), 'risk_policy' => self::RISK], $extra)]]);
    }

    private static function params(): array
    {
        return ['amount' => 1000, 'charge' => 'ch_abcdefgh', 'idempotency_key' => 'k1'];
    }

    private static function ctx(Obj $doc, array $over = []): Obj
    {
        return Obj::of(array_merge(['policy' => self::o(['schema' => ['closed_world' => true]]), 'schema' => Obj::of(['docs' => [$doc], 'keys' => self::keys()]),
            'reviewers' => self::vector('rule22-conf-allow')->get('pins'), 'call_context' => self::CONTEXT, 'params' => self::o(self::params())], $over));
    }

    /** @return array<string,true|string> */
    private static function decide(Obj $doc, Obj $grant, Obj $ctx, string $verb = self::VERB, ?array $params = null): array
    {
        $p = Obj::of(['aud' => $doc->get('aud'), 'action' => Obj::of(['verb' => $verb, 'resource' => 'x', 'params_digest' => Pca::paramsDigest(self::o($params ?? self::params()))])]);
        $out = [];
        foreach (IntentV2::decideIntentV2($p, $grant, $ctx, 0)['checks'] as $c) {
            $out[$c['name']] = $c['ok'] ? true : $c['reason'];
        }
        return $out;
    }

    private static function pinned(array $over = [], array $ctxOver = []): array
    {
        $d = self::doc();
        return self::decide($d, self::grant(['actions' => self::pin($over)]), self::ctx($d, $ctxOver));
    }

    public function testControlReportsPinThenTraitsInOrder(): void
    {
        $this->assertSame(['schema' => true, 'pin' => true, 'traits' => true], self::pinned());
        $d = self::doc();
        $r = self::decide($d, self::grant(['actions' => self::pin(), 'units' => []]), self::ctx($d));
        $this->assertSame(['schema', 'pin', 'traits', 'units'], array_keys($r));
    }

    public function testForgedDocumentsAreRefusedByTheSchemaStepAndThePin(): void
    {
        foreach (['rule22-forged-floors-denied' => 'schema_floor_forged', 'rule22-dropped-traits-denied' => 'schema_traits_forged',
            'rule22-schema-trait-unknown' => 'unknown_trait', 'rule22-schema-traits-digest-wrong' => 'traits_digest_mismatch'] as $v => $code) {
            $d = self::doc($v);
            $pins = self::vector($v)->has('pins') ? self::vector($v)->get('pins') : self::o(['keys' => []]);
            $r = self::decide($d, self::grant(['actions' => self::pin()]), self::ctx($d, ['reviewers' => $pins]));
            $this->assertSame(['schema', 'pin'], array_keys($r), $v); // a failed schema step reports no traits
            $this->assertStringStartsWith('schema_floor_forged: ', $r['schema'], $v);
            $this->assertStringContainsString($code, $r['schema'], $v);
            $this->assertSame($r['schema'], $r['pin'], $v);
        }
    }

    public function testConfirmationNeedsTheVerifierReviewerPins(): void
    {
        $d = self::doc();
        $this->assertTrue(self::decide($d, self::grant(), self::ctx($d))['schema']);
        $ctx = self::ctx($d);
        $noPins = Obj::of(['policy' => $ctx->get('policy'), 'schema' => $ctx->get('schema'), 'call_context' => self::CONTEXT, 'params' => $ctx->get('params')]);
        $r = self::decide($d, self::grant(), $noPins);
        $this->assertStringStartsWith('schema_floor_forged: ', $r['schema']);
        $this->assertStringContainsString('schema_traits_forged', $r['schema']);
    }

    public function testIntegrityPositionIsAfterAudBeforeParams(): void
    {
        $d = self::vector('rule22-forged-floors-denied')->get('doc');
        $d->set('aud', 'other');
        $signed = self::signed(IntentV2::ACTION_SCHEMA_DOMAIN, $d);
        $p = Obj::of(['aud' => 'mine', 'action' => Obj::of(['verb' => self::VERB, 'resource' => 'x', 'params_digest' => 'nope'])]);
        $ctx = Obj::of(['policy' => self::o(['schema' => ['closed_world' => true]]), 'schema' => Obj::of(['docs' => [$signed], 'keys' => self::keys()])]);
        $this->assertSame('schema aud does not match the PCActn aud', IntentV2::decideIntentV2($p, null, $ctx, 0)['checks'][0]['reason']);
        $p->set('aud', 'other');
        $this->assertStringStartsWith('schema_floor_forged: ', IntentV2::decideIntentV2($p, null, $ctx, 0)['checks'][0]['reason']); // no params: forged first
    }

    public function testFloorDecisionMeetsTheGrant(): void
    {
        $this->assertSame(self::EXCEED, self::pinned(['max_esc' => 1, 'preauth_esc' => 0])['traits']);
        $this->assertSame(self::ESCALATE, self::pinned(['preauth_esc' => 1])['traits']);
        $this->assertSame(self::ESCALATE, self::pinned(['caveats' => []])['traits']);
        $this->assertSame(self::ESCALATE, self::pinned([], ['call_context' => ['fresh_revocation']])['traits']);
    }

    public function testDefaultsWithoutAPin(): void
    {
        // no pin: max_esc MAX_ESC_TIER, preauth_esc 0, the envelope caveats only; esc 2 > 0 escalates
        $d = self::doc();
        $r = self::decide($d, self::grant(), self::ctx($d));
        $this->assertSame(['schema' => true, 'traits' => self::ESCALATE], $r);
    }

    public function testPinDefaultsAndCaveatSources(): void
    {
        $pin = self::pin();
        unset($pin['max_esc']);
        $d = self::doc();
        $this->assertTrue(self::decide($d, self::grant(['actions' => $pin]), self::ctx($d))['traits']); // max_esc defaults to 3 >= esc 2
        $pin = self::pin();
        unset($pin['preauth_esc']);
        $this->assertSame(self::ESCALATE, self::decide($d, self::grant(['actions' => $pin]), self::ctx($d))['traits']); // preauth_esc defaults to 0
        $pin = self::pin();
        unset($pin['caveats']);
        $this->assertSame(self::ESCALATE, self::decide($d, self::grant(['actions' => $pin]), self::ctx($d))['traits']);
        // envelope caveat types and pin caveats both count; a member that is no string type is ignored
        $pin = self::pin(['caveats' => ['count_cap', 'window']]);
        $g = self::grant(['actions' => $pin, 'caveats' => [['type' => 'amount_cap'], ['type' => 5], ['x' => 1], 's']]);
        $this->assertTrue(self::decide($d, $g, self::ctx($d))['traits']);
        $g = self::grant(['actions' => $pin, 'caveats' => [['type' => 5], ['x' => 1], 's']]);
        $this->assertSame(self::ESCALATE, self::decide($d, $g, self::ctx($d))['traits']);
    }

    public function testAnInvalidPinFailsAndItsMembersAreNotUsed(): void
    {
        $r = self::pinned(['on_new_action' => 'maybe']);
        $this->assertStringStartsWith('bad_pin: ', $r['pin']);
        $this->assertSame(self::ESCALATE, $r['traits']); // preauth_esc 2 of the invalid pin is not read
    }

    public function testPinReasons(): void
    {
        $this->assertSame("new_action: the grant does not name '" . self::VERB . "' (on_new_action: deny)", self::pinned(['defs' => ['acme.x.y' => self::DEF]])['pin']);
        $this->assertSame("escalate: new_action: the grant does not name '" . self::VERB . "' (on_new_action: escalate)",
            self::pinned(['defs' => ['acme.x.y' => self::DEF], 'on_new_action' => 'escalate'])['pin']);
        $other = str_repeat('B', 43);
        $this->assertSame('def_changed: the definition differs from the pinned digest and no signed evolution record chains to it', self::pinned(['defs' => [self::VERB => $other]])['pin']);
        $pack = self::pin();
        unset($pack['defs']);
        $d = self::doc();
        $this->assertTrue(self::decide($d, self::grant(['actions' => $pack]), self::ctx($d))['pin']); // a pack-level pin at the exact root
    }

    private static function record(string $from, string $class): Obj
    {
        return self::signed(ActionsRegistry::EVOLUTION_DOMAIN, self::o(['v' => 1, 'kind' => ActionsRegistry::EVOLUTION_RECORD_KIND, 'ns' => 'stripe', 'verb' => self::VERB,
            'from' => $from, 'to' => self::DEF, 'class' => $class, 'reasons' => []]));
    }

    public function testEvolutionContextReachesThePin(): void
    {
        $from = str_repeat('B', 43);
        $pin = ['defs' => [self::VERB => $from]];
        $keys = self::keys();
        // a signed narrowing chains: records and keys both come from the context
        $this->assertTrue(self::pinned($pin, ['actions' => Obj::of(['records' => [self::record($from, 'narrow')], 'keys' => $keys])])['pin']);
        $this->assertStringStartsWith('def_changed: ', self::pinned($pin, ['actions' => Obj::of(['records' => [self::record($from, 'narrow')]])])['pin']);
        // a widening names the diff to approve
        $w = self::record($from, 'widen');
        $diff = ActionsRegistry::evolutionDiffDigest($w);
        $this->assertSame("def_changed: the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve (re-approve diff $diff)",
            self::pinned($pin, ['actions' => Obj::of(['records' => [$w], 'keys' => $keys])])['pin']);
    }

    public function testASchemaOnlyReadByThePinStillReportsTraits(): void
    {
        // no closed_world and no intent_session: no `schema` check, the pin's own schema step decides that traits run
        $d = self::doc();
        $ctx = self::ctx($d);
        $open = Obj::of(['schema' => $ctx->get('schema'), 'reviewers' => $ctx->get('reviewers'), 'call_context' => self::CONTEXT, 'params' => $ctx->get('params')]);
        $this->assertSame(['pin' => true, 'traits' => true], self::decide($d, self::grant(['actions' => self::pin()]), $open));
        $this->assertSame([], self::decide($d, self::grant(), $open));
        // a throw in that schema step fails the pin check and reports no traits
        IntentV2::$faultHook = static function (string $at): void {
            if ($at === 'schema_for') {
                throw new \RuntimeException('boom');
            }
        };
        try {
            $this->assertSame(['pin' => 'pin error (fail closed): boom'], self::decide($d, self::grant(['actions' => self::pin()]), $open));
        } finally {
            IntentV2::$faultHook = null;
        }
    }

    private static function kt(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentV2KillTest::class, $m))->invokeArgs(null, $a);
    }

    public function testAV1SchemaGetsNoTraitsCheck(): void
    {
        $doc = self::kt('schema');
        $params = self::kt('params');
        $p = Obj::of(['aud' => self::kt('aud'), 'action' => Obj::of(['verb' => 'air.book', 'resource' => 'x', 'params_digest' => Pca::paramsDigest($params)])]);
        $ctx = Obj::of(['policy' => self::o(['schema' => ['closed_world' => true]]), 'schema' => Obj::of(['docs' => [$doc], 'keys' => self::kt('keys')]), 'params' => $params]);
        $names = static fn(array $d): array => array_column($d['checks'], 'name');
        $this->assertSame(['schema'], $names(IntentV2::decideIntentV2($p, self::grant(), $ctx, 0)));
        $r = IntentV2::decideIntentV2($p, self::grant(['actions' => self::pin()]), $ctx, 0);
        $this->assertSame(['schema', 'pin'], $names($r));
        $this->assertTrue($r['checks'][0]['ok']);
        $this->assertSame("pack_mismatch: the schema does not come from the pinned pack 'stripe'", $r['checks'][1]['reason']);
    }

    /** TS intent-v2.ts:613: the schema step runs once per decision, even if the verifier's configuration moves under it. */
    public function testTheSchemaStepIsMemoized(): void
    {
        $d = self::doc();
        $ctx = self::ctx($d);
        $schema = $ctx->get('schema');
        $open = Obj::of(['schema' => $schema, 'reviewers' => $ctx->get('reviewers'), 'call_context' => self::CONTEXT, 'params' => $ctx->get('params')]);
        $n = 0;
        IntentV2::$faultHook = static function (string $at) use (&$n, $schema): void {
            if ($at === 'schema_for' && ++$n === 2) {
                $schema->set('docs', []); // a second schema step would now refuse
            }
        };
        try {
            $this->assertSame(['pin' => true, 'traits' => true], self::decide($d, self::grant(['actions' => self::pin()]), $open));
        } finally {
            IntentV2::$faultHook = null;
        }
    }

    /** A widened definition passes only on a re-approval that names this grant: decidePin receives the grant's own id. */
    public function testAReapprovalIsBoundToTheGrantId(): void
    {
        $old = str_repeat('A', 43);
        $rec = self::signed(ActionsRegistry::EVOLUTION_DOMAIN, self::o(['v' => 1, 'kind' => ActionsRegistry::EVOLUTION_RECORD_KIND, 'ns' => 'stripe', 'verb' => self::VERB,
            'from' => $old, 'to' => self::DEF, 'class' => 'widen', 'reasons' => []]));
        $diff = ActionsRegistry::evolutionDiffDigest($rec);
        $reapproval = static function (string $grant) use ($diff): Obj {
            $r = self::o(['v' => 1, 'kind' => ActionsRegistry::REAPPROVAL_KIND, 'grant' => $grant, 'verb' => self::VERB, 'diff' => $diff]);
            $r->set('sig', self::o(['alg' => 'ed25519', 'value' => Pca::b64u(sodium_crypto_sign_detached(ActionsRegistry::REAPPROVAL_DOMAIN . IntentV2::canonicalize($r), self::kp()[1]))]));
            return $r;
        };
        $d = self::doc();
        $g = self::grant(['actions' => self::pin(['defs' => [self::VERB => $old]])]);
        $g->set('issuer', self::kp()[0]);
        $decide = fn(string $named): array => self::decide($d, $g, self::ctx($d, ['actions' => Obj::of(['records' => [$rec], 'keys' => self::keys(), 'reapprovals' => [$reapproval($named)]])]));
        $this->assertTrue($decide($g->get('id'))['pin']);
        $this->assertStringStartsWith('def_changed: the definition widened', $decide(str_repeat('H', 43))['pin']);
    }

    /** No envelope at all: rule 22 still runs on a v2 schema, with no caveats (TS intent-v2.ts:630 `env?.caveats`). */
    public function testTraitsRunWithoutAnEnvelope(): void
    {
        $d = self::doc();
        $g = self::o(['id' => str_repeat('G', 43), 'issuer' => str_repeat('I', 43), 'caveats' => []]);
        $this->assertSame(self::ESCALATE, self::decide($d, $g, self::ctx($d))['traits']);
    }

    /** gmail.send has esc 1, so a preauth_esc default above 0 would allow it (TS intent-v2.ts:631 `pin?.preauth_esc ?? 0`). */
    public function testPreauthDefaultsToZeroOnAFloorOfOne(): void
    {
        $verb = 'gmail.send';
        $params = ['body' => 'hello', 'idempotency_key' => 'k1', 'subject' => 'hi', 'to' => 'a@b.example'];
        $d = self::doc('rule22-allow');
        $ctx = self::ctx($d, ['params' => self::o($params)]);
        $pin = self::pin(['defs' => [$verb => 'b5ugs3av92AWwc9DZHVRxoHyrb20GLOLDhAG4ma2RtE'], 'caveats' => ['rate_cap', 'recipient_scope', 'resource_scope'], 'preauth_esc' => 1]);
        $this->assertTrue(self::decide($d, self::grant(['actions' => $pin]), $ctx, $verb, $params)['traits']);
        unset($pin['preauth_esc']);
        $this->assertSame(self::ESCALATE, self::decide($d, self::grant(['actions' => $pin]), $ctx, $verb, $params)['traits']);
    }

    public function testContextValidation(): void
    {
        $err = static fn(array $c): ?string => IntentV2::intentV2ContextError(self::o($c));
        foreach ([[], 'k', new \stdClass(), ['keys' => 'x']] as $bad) {
            $this->assertSame('reviewers must be {keys: [...]}', $err(['reviewers' => $bad, 'params' => 1]));
        }
        $this->assertNull($err(['reviewers' => ['keys' => []]]));
        foreach (['fresh_revocation', [1], null, ['a', 1]] as $bad) {
            $this->assertSame('call_context must be an array of strings', $err(['call_context' => $bad, 'params' => 1]));
        }
        $this->assertNull($err(['call_context' => ['a']]));
        $this->assertSame('actions must be an object', $err(['actions' => [], 'params' => 1]));
        foreach (['records', 'keys', 'reapprovals'] as $k) {
            $this->assertSame("actions.$k must be an array", $err(['actions' => [$k => 'x'], 'params' => 1]));
        }
        $this->assertNull($err(['actions' => ['records' => [], 'keys' => [], 'reapprovals' => []]]));
        $this->assertSame('params must be an object', $err(['params' => 1]));
    }
}
