<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Mutation-kill tests for Intent Layer v2 W-A in src/IntentV2.php and its integration in src/Pca.php / PcaMiddleware.php:
 * the `intent_session` wire slot, the v2 goal (rule 13 amends rule 12 step 2), the policy-layer `intent_session` caveat,
 * rule 14 (schema shape / signature / closed-world conformance), rule 13 (bound root, delta chain, revocation epoch and
 * non-membership), rule 15 (accumulators, monitors, receipts), the strict context rules (absent vs null, unsupported_suite),
 * reporting and pipeline order. Every artifact is signed in-test (Ed25519, libsodium) from fixed seeds; every boundary is
 * pinned on both sides and the first failing step is asserted where two steps fail.
 */
final class IntentV2KillTest extends TestCase
{
    private const MAX_SAFE = 9007199254740991;
    private const CORE = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter'];
    private const SALT = 'salt0';
    private const UNIT = 'spend.usd_cents';

    // ---- keys, digests, signing -------------------------------------------------------------------------------------

    /** @return array{0:string,1:string} [public b64u, secret key] from keys.json (principal, agent, ...) or a labelled seed. */
    private static function key(string $name): array
    {
        $keys = json_decode(file_get_contents(Corpus::DIR . 'keys.json'), true);
        $seed = isset($keys[$name]) ? Pca::unb64u($keys[$name]['seed']) : hash('sha256', "php-intent-v2-kill/$name", true);
        $kp = sodium_crypto_sign_seed_keypair($seed);
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function pub(string $name): string
    {
        return self::key($name)[0];
    }

    private static function sign(string $name, string $msg): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($msg, self::key($name)[1]));
    }

    private static function d(string $label): string
    {
        return Pca::b64u(hash('sha256', $label, true));
    }

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(self::enc($a));
    }

    /**
     * JSON text of a PHP value that may NEST already-parsed Obj / Num nodes (signed schemas, roots, grants embedded in a
     * context). Plain json_encode cannot: Obj keeps its members in private properties (encoded as `{}`) and Num encodes as
     * `{"lexeme": ...}`, which silently emptied every nested document and failed 17 tests on every host.
     */
    private static function enc(mixed $a): string
    {
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION | JSON_THROW_ON_ERROR;
        if ($a instanceof Obj) {
            $parts = [];
            foreach ($a->keys() as $k) {
                $parts[] = json_encode((string)$k, $flags) . ':' . self::enc($a->get($k));
            }
            return '{' . implode(',', $parts) . '}';
        }
        if ($a instanceof Num) {
            return $a->lexeme;
        }
        if ($a instanceof \stdClass) {
            $a = get_object_vars($a);
            if ($a === []) {
                return '{}';
            }
        }
        if (is_array($a)) {
            if ($a !== [] && array_is_list($a) || $a === []) {
                return '[' . implode(',', array_map([self::class, 'enc'], $a)) . ']';
            }
            $parts = [];
            foreach ($a as $k => $v) {
                $parts[] = json_encode((string)$k, $flags) . ':' . self::enc($v);
            }
            return '{' . implode(',', $parts) . '}';
        }
        return json_encode($a, $flags);
    }

    private static function ctxNow(): int
    {
        return self::vector()->get('context')->get('now')->int();
    }

    private static function aud(): string
    {
        return self::vector()->get('context')->get('aud');
    }

    private static function vector(): Obj
    {
        static $v = null;
        if ($v === null) {
            foreach (Corpus::core()->get('vectors') as $x) {
                if ($x->get('name') === 'valid-in-plan-action') {
                    $v = $x;
                }
            }
        }
        return $v;
    }

    private static function session(): string
    {
        return self::d('ki2/session');
    }

    private static function ref(): string
    {
        return self::d('ki2/ref');
    }

    private static function map0(): string
    {
        return self::d('ki2/map0');
    }

    // ---- the schema -----------------------------------------------------------------------------------------------

    private static function unsignedSchema(array $over = []): array
    {
        return array_merge([
            'v' => 1, 'kind' => 'pca-action-schema', 'site' => 'https://skyair.example', 'aud' => self::aud(), 'version' => '2026-10-01',
            'units' => ['usd_cents' => ['kind' => 'money', 'currency' => 'USD', 'exponent' => 2]],
            'verbs' => [
                ['verb' => 'air.book', 'kind' => 'write', 'params' => [
                    'action.params.offer_id' => ['type' => 'string', 'semantic' => 'product.ref', 'sensitivity' => 'material'],
                    'action.params.total' => ['type' => 'integer', 'unit' => 'usd_cents', 'min' => 0, 'max' => 5000000, 'semantic' => 'money.amount',
                        'sensitivity' => 'critical', 'accumulates_into' => [self::UNIT]],
                    'action.params.add_ons' => ['type' => 'set', 'values' => ['none', 'tripshield', 'seat_plus'], 'semantic' => 'product.addon', 'sensitivity' => 'material'],
                    'action.params.refundable' => ['type' => 'boolean', 'semantic' => 'flag', 'sensitivity' => 'material'],
                    'action.params.passengers' => ['type' => 'array', 'max_items' => 9, 'max_len' => 64, 'semantic' => 'person.identity',
                        'sensitivity' => 'critical', 'required' => false],
                    'action.params.note' => ['type' => 'string', 'semantic' => 'text.note', 'sensitivity' => 'free', 'required' => false, 'max_len' => 16],
                ]],
                ['verb' => 'air.search', 'kind' => 'read', 'params' => [
                    'action.params.from' => ['type' => 'string', 'values' => ['SFO', 'JFK'], 'semantic' => 'place.airport', 'sensitivity' => 'material'],
                    'action.params.date' => ['type' => 'date', 'semantic' => 'schedule.date', 'sensitivity' => 'material'],
                    'action.params.pax' => ['type' => 'integer', 'min' => 1, 'max' => 9, 'semantic' => 'quantity', 'sensitivity' => 'material'],
                ], 'reversibility' => 'reversible'],
            ],
        ], $over);
    }

    /** A site-signed schema (sig over "atlas-pca/action-schema/v1\0" || strictCanonical(doc without sig)). */
    private static function schema(array $over = [], string $signer = 'site', array $sigOver = []): Obj
    {
        $doc = self::o(self::unsignedSchema($over));
        $sig = array_merge(['alg' => 'ed25519', 'kid' => 'k1'], $sigOver);
        $sig['value'] = self::sign($signer, IntentV2::ACTION_SCHEMA_DOMAIN . IntentV2::canonicalize($doc));
        $doc->set('sig', self::o($sig));
        return $doc;
    }

    private static function keys(string $signer = 'site'): array
    {
        return [self::o(['kid' => 'k1', 'alg' => 'ed25519', 'pk' => self::pub($signer)])];
    }

    private static function params(array $over = []): Obj
    {
        return self::o(array_merge(['offer_id' => 'OF-1', 'total' => 38900, 'add_ons' => ['none'], 'refundable' => false], $over));
    }

    // ---- the session root, grants, PCActn -----------------------------------------------------------------------------

    private static function trip(array $over = []): array
    {
        return array_merge(['id' => 'trip_spend', 'agg' => 'sum', 'unit' => 'usd_cents', 'sel' => ['accumulates_into' => self::UNIT],
            'win' => ['kind' => 'task'], 'key' => null, 'domain_max' => 500000, 'holder' => ['kind' => 'site_local']], $over);
    }

    private static function questions(): array
    {
        return ['id' => 'questions', 'agg' => 'count', 'sel' => ['event' => 'intent_required'], 'win' => ['kind' => 'task'], 'key' => null,
            'cap' => 6, 'holder' => ['kind' => 'wallet']];
    }

    private static function rootBody(array $over = []): array
    {
        return array_merge([
            'v' => 1, 'kind' => 'pca-intent-session', 'session' => self::session(), 'principals' => [['key' => self::pub('principal')]],
            'intent_ref' => self::ref(), 'schema' => ['aud' => self::aud(), 'digest' => IntentV2::actionSchemaDigest(self::schema())],
            'layers' => ['task' => ['map_digest' => self::map0()]], 'accumulators' => [self::trip(), self::questions()], 'monitors' => [],
            'question_uri' => 'https://atlas.example/q', 'expires_at' => self::ctxNow() + 86400000,
        ], $over);
    }

    /** A principal-signed session root S (over "atlas-pca/intent-session/v1\0" || strictCanonical(body + signer)). */
    private static function root(array $over = [], string $signer = 'principal'): Obj
    {
        $s = self::o(array_merge(self::rootBody($over), ['signer' => self::pub($signer)]));
        $s->set('sig', self::sign($signer, IntentV2::INTENT_SESSION_SIG_DOMAIN . IntentV2::canonicalize($s)));
        return $s;
    }

    /** A root capability (issuer `$signer`, holder agent) carrying the v2 envelope and the session caveat. */
    private static function grant(int $seq = 0, ?string $prev = null, ?Obj $S = null, string $signer = 'principal', ?string $map = null,
                                  ?string $salt = null, ?array $sc = null, ?string $goalSession = null, ?string $mapForm = null): Obj
    {
        $R = IntentV2::sessionRootDigest($S ?? self::root());
        $sc ??= array_merge(['type' => 'intent_session', 'session' => self::session(), 'seq' => $seq, 'root' => $R],
            $prev !== null ? ['prev' => $prev] : []);
        $goal = Pca::intentGoalCommit(self::ref(), $map ?? self::map0(), $salt ?? self::SALT, $goalSession ?? self::session(), $mapForm);
        $caveats = [['type' => 'envelope', 'goal_commit' => $goal], $sc];
        $issuer = self::pub($signer);
        $holder = self::pub('agent');
        $digest = Pca::hashCanonical(self::o(['issuer' => $issuer, 'holder' => $holder, 'caveats' => $caveats, 'parent' => null]));
        return self::o(['id' => $digest, 'issuer' => $issuer, 'holder' => $holder, 'body_digest' => $digest, 'caveats' => $caveats,
            'sig' => self::sign($signer, Pca::CAP_DOMAIN . Pca::unb64u($digest, 32))]);
    }

    private static function intentSession(array $over = [], ?Obj $S = null): array
    {
        return array_merge(['session' => self::session(), 'root' => IntentV2::sessionRootDigest($S ?? self::root()), 'seq' => 0,
            'schema' => IntentV2::actionSchemaDigest(self::schema()), 'acc' => [['id' => 'trip_spend', 'post' => 38900]]], $over);
    }

    /** The corpus PCActn re-rooted at `$grant`, acting `air.book` on `$params` (single-leaf plan), carrying intent + `$is`. */
    private static function pcactn(Obj $grant, ?array $is, ?Obj $params = null, ?string $map = null): Obj
    {
        $p = Json::parseLax(Json::canonicalizeStrict(self::vector()->get('pcactn')));
        $pd = IntentV2::hashCanonical($params ?? self::params());
        $p->set('action', self::o(['verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => $pd,
            'reversibility_class' => 'irreversible']));
        $cond = self::d('ki2/cond');
        $leaf = self::o(['node_id' => 'book', 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => $pd,
            'reversibility_class' => 'irreversible', 'conditions' => $cond]);
        $p->set('plan', self::o(['root' => Pca::merkleRoot([$leaf]), 'inclusion_proof' => ['index' => 0, 'size' => 1, 'path' => []],
            'node_id' => 'book', 'conditions_digest' => $cond]));
        $p->set('cap_chain', [$grant]);
        $p->set('grant_ref', $grant->get('id'));
        $p->set('intent', self::o(['ref' => self::ref(), 'map_digest' => $map ?? self::map0(), 'goal_salt' => self::SALT,
            'fidelity_ppm' => 1000000, 'residual_risk_ppm' => 0]));
        if ($is !== null) {
            $p->set('intent_session', self::o($is));
        }
        $p->set('sig', self::sign('agent', Pca::thresholdMessage($p)));
        return $p;
    }

    private static function ctx(array $over = []): Obj
    {
        return self::o(array_merge([
            'params' => self::params(), 'schema' => ['docs' => [self::schema()], 'keys' => self::keys()],
            'session' => ['root' => self::root(), 'grants' => []],
            'acc' => ['state' => ['trip_spend' => ['sum' => 0]], 'monitors' => (object)[]],
        ], $over));
    }

    private static function verify(Obj $p, Obj $grant, ?Obj $ctx, ?int $now = null): array
    {
        return Pca::verifyPcactnCore($p, $grant, $now ?? self::ctxNow(), self::aud(), null, null, $ctx);
    }

    private static function v2(Obj $p, Obj $grant, mixed $ctx, ?int $now = null): array
    {
        $out = [];
        foreach (IntentV2::decideIntentV2($p, $grant, $ctx, $now ?? self::ctxNow())['checks'] as $c) {
            $out[$c['name']] = $c['ok'] ? true : $c['reason'];
        }
        return $out;
    }

    private static function base(): array
    {
        $g = self::grant();
        return [$g, self::pcactn($g, self::intentSession())];
    }

    // ==== baseline, reporting, pipeline order ==========================================================================

    public function testBaselineAllowsAndReportsV2ChecksInOrder(): void
    {
        [$g, $p] = self::base();
        $r = self::verify($p, $g, self::ctx());
        $this->assertTrue($r['allow'], $r['reason']);
        $this->assertSame([...self::CORE, 'intent', 'schema', 'intent_session', 'accumulators'], array_keys($r['checks']));
        $d = IntentV2::decideIntentV2($p, $g, self::ctx(), self::ctxNow());
        $this->assertSame('38900', $d['env']->get('acc')->get('trip_spend')->get('post')->lexeme);
        $this->assertSame('false', $d['env']->get('canon')->get('refundable'));
        $this->assertSame('["none"]', $d['env']->get('canon')->get('add_ons'));
        $this->assertInstanceOf(Obj::class, $d['schema']);
    }

    public function testBackCompatNothingReportedWithoutMemberOrPolicy(): void
    {
        $g = self::grant(sc: ['type' => 'intent_session', 'session' => self::session(), 'seq' => 0, 'root' => self::d('x')]);
        $p = self::pcactn($g, null);
        $this->assertSame([], IntentV2::decideIntentV2($p, $g, null, self::ctxNow())['checks']);
        $this->assertSame([], IntentV2::decideIntentV2($p, $g, self::ctx(), self::ctxNow())['checks']);
        $this->assertFalse(IntentV2::intentV2Active($p, self::ctx()));
        $this->assertTrue(IntentV2::intentV2Active(self::base()[1], null));
    }

    public function testPoliciesActivateTheirChecksOnly(): void
    {
        $g = self::grant();
        $p = self::pcactn($g, null);
        $req = self::ctx(['policy' => ['session' => ['require' => true]]]);
        $this->assertSame(['intent_session' => 'this verifier requires an intent_session but the PCActn carries none'], self::v2($p, $g, $req));
        $this->assertTrue(IntentV2::intentV2Active($p, $req));
        $cw = self::v2($p, $g, self::ctx(['policy' => ['schema' => ['closed_world' => true]]]));
        $this->assertSame(['schema' => true], $cw); // closed world: checked against the FIRST schema
        $cw2 = self::v2($p, $g, self::ctx(['policy' => ['schema' => ['closed_world' => true]], 'params' => self::params(['total' => 1])]));
        $this->assertSame(['schema' => 'params do not hash to action.params_digest'], $cw2);
        // explicit false = inactive; a non-boolean flag, a bad age or an unknown member makes the context malformed
        $this->assertSame([], self::v2($p, $g, self::ctx(['policy' => ['session' => ['require' => false], 'schema' => ['closed_world' => false]]])));
        $bad = [
            [['session' => ['require' => 1]], 'policy.session.require must be a boolean'],
            [['session' => ['require' => null]], 'policy.session.require must be a boolean'],
            [['schema' => ['closed_world' => 'true']], 'policy.schema.closed_world must be a boolean'],
            [['session' => ['max_revocation_age_s' => null]], 'policy.session.max_revocation_age_s must be a non-negative safe integer'],
            [['session' => ['max_revocation_age_s' => -1]], 'policy.session.max_revocation_age_s must be a non-negative safe integer'],
            [['session' => ['x' => true]], "policy.session: unknown member 'x'"],
            [['schema' => ['x' => true]], "policy.schema: unknown member 'x'"],
            [['other' => (object)[]], "policy: unknown member 'other'"],
            [['session' => null], 'policy.session must be an object'],
            [['schema' => []], 'policy.schema must be an object'],
        ];
        foreach ($bad as $i => [$pol, $why]) {
            $r = self::v2($p, $g, self::ctx(['policy' => $pol]));
            $this->assertSame(['schema' => "malformed v2 context: $why", 'intent_session' => "malformed v2 context: $why"], $r, "case $i");
        }
        $this->assertNull(IntentV2::intentV2ContextError(self::o(['policy' => ['session' => ['max_revocation_age_s' => 0]]])));
    }

    public function testLayersReportedOnlyWithMemberAndConfiguredLayers(): void
    {
        [$g, $p] = self::base();
        $admit = self::v2($p, $g, self::ctx(['layers' => ['org' => ['predicates' => [['verb' => 'air.book', 'resource' => '*']]]]]));
        $this->assertSame(['schema', 'intent_session', 'layers', 'accumulators'], array_keys($admit));
        $this->assertTrue($admit['layers']);
        $deny = self::v2($p, $g, self::ctx(['layers' => ['org' => ['predicates' => []]]]));
        $this->assertIsString($deny['layers']);
        $this->assertTrue($deny['accumulators']); // checks 1-4 are independent
        $this->assertTrue(self::v2($p, $g, self::ctx(['layers' => (object)[]]))['layers']);
    }

    public function testChecksOneToFourAreIndependent(): void
    {
        [$g, $p] = self::base();
        $r = self::v2($p, $g, self::ctx(['schema' => ['docs' => [], 'keys' => []]]));
        $this->assertSame('this verifier has no action schema configured', $r['schema']);
        $this->assertTrue($r['intent_session']);
        // the schema doc is unavailable for accumulates_into selection: accumulators fail on their own
        $this->assertSame("accumulator 'trip_spend' selects by accumulates_into but the session schema is not available", $r['accumulators']);
        $v = self::verify($p, $g, self::ctx(['schema' => ['docs' => [], 'keys' => []]]));
        $this->assertFalse($v['allow']);
        $this->assertStringStartsWith('schema: ', $v['reason']); // the first failing v2 check names the reason
    }

    public function testMalformedContextFailsEveryReportableCheck(): void
    {
        [$g, $p] = self::base();
        foreach ([['params' => null], ['policy' => null], ['policy' => ['session' => null]], ['schema' => 'x'], ['acc' => []],
                     ['layers' => ['org' => null]], ['layers' => ['xyz' => ['predicates' => []]]], ['wb' => ['artifacts' => ['facts' => (object)[]]]],
                     ['wb' => ['policy' => ['classifiers' => null]]]] as $i => $bad) {
            $r = self::v2($p, $g, self::ctx($bad));
            $this->assertSame(['schema', 'intent_session', 'accumulators'], array_keys($r), "case $i");
            foreach ($r as $why) {
                $this->assertStringStartsWith('malformed v2 context: ', $why, "case $i");
            }
        }
        $np = self::pcactn($g, null);
        $this->assertSame(['schema', 'intent_session'], array_keys(self::v2($np, $g, self::ctx(['params' => null]))));
        $this->assertSame('malformed v2 context: the v2 verifier context must be an object', self::v2($p, $g, [])['schema'] ?? null);
    }

    public function testClockMustBeSafeInteger(): void
    {
        [$g, $p] = self::base();
        $r = self::v2($p, $g, self::ctx(), self::MAX_SAFE + 1);
        foreach ($r as $why) {
            $this->assertSame('the verifier clock is not a safe integer (fail closed)', $why);
        }
        $this->assertArrayHasKey('accumulators', $r);
    }

    // ==== wire slot =====================================================================================================

    private static function wire(array $over): ?string
    {
        return IntentV2::validateIntentSessionWire(self::o(self::intentSession($over)));
    }

    public function testWireEdges(): void
    {
        $this->assertNull(self::wire([]));
        $this->assertNull(self::wire(['seq' => 2147483647, 'acc' => []]));
        $this->assertSame("'intent_session.seq' must be a safe integer in [0, 2147483647]", self::wire(['seq' => 2147483648]));
        $this->assertSame("'intent_session.seq' must be a safe integer in [0, 2147483647]", self::wire(['seq' => -1]));
        $neg = self::o(self::intentSession());
        $neg->set('seq', new Num('-0'));
        $this->assertSame("'intent_session.seq' must be a safe integer in [0, 2147483647]", IntentV2::validateIntentSessionWire($neg));
        $one = self::o(self::intentSession());
        $one->set('seq', new Num('1.0'));
        $this->assertNull(IntentV2::validateIntentSessionWire($one)); // by value
        $this->assertSame("'intent_session' must be an object", IntentV2::validateIntentSessionWire([]));
        $this->assertSame("unknown field 'intent_session.x'", self::wire(['x' => 1]));
        $m = self::o(self::intentSession());
        $m = $m->without('schema');
        $this->assertSame("missing field 'intent_session.schema'", IntentV2::validateIntentSessionWire($m));
        $this->assertSame("'intent_session.session' is not canonical base64url (32 bytes)", self::wire(['session' => 'x', 'root' => 'y']));
    }

    public function testWireAccClaims(): void
    {
        $acc = fn(int $n) => array_map(fn($i) => ['id' => "a$i", 'post' => 0], range(1, $n));
        $this->assertNull(self::wire(['acc' => $acc(16)]));
        $this->assertSame("'intent_session.acc' must be an array of at most 16 entries", self::wire(['acc' => $acc(17)]));
        $this->assertSame("'intent_session.acc' must be an array of at most 16 entries", self::wire(['acc' => null]));
        $this->assertSame("'intent_session.acc' ids must be distinct", self::wire(['acc' => [['id' => 'a', 'post' => 0], ['id' => 'a', 'post' => 1]]]));
        $this->assertSame("'intent_session.acc[0].id' must match [A-Za-z0-9_]{1,64}", self::wire(['acc' => [['id' => str_repeat('a', 65), 'post' => 0]]]));
        $this->assertSame("'intent_session.acc[0].id' must match [A-Za-z0-9_]{1,64}", self::wire(['acc' => [['id' => "a\n", 'post' => 0]]]));
        $this->assertNull(self::wire(['acc' => [['id' => str_repeat('a', 64), 'post' => self::MAX_SAFE]]]));
        $this->assertSame("'intent_session.acc[0].post' must be a non-negative safe integer", self::wire(['acc' => [['id' => 'a', 'post' => -1]]]));
        $this->assertSame("'intent_session.acc[0].post' must be a non-negative safe integer", self::wire(['acc' => [['id' => 'a', 'post' => '1']]]));
        $this->assertSame("'intent_session.acc[0].receipt' is not canonical base64url (32 bytes)", self::wire(['acc' => [['id' => 'a', 'post' => 0, 'receipt' => null]]]));
        $this->assertSame("unknown field 'intent_session.acc[0].x'", self::wire(['acc' => [['id' => 'a', 'post' => 0, 'x' => 1]]]));
    }

    public function testWireDigestListsAndProv(): void
    {
        $ds = fn(int $n) => array_map(fn($i) => self::d("f$i"), range(1, $n));
        $this->assertNull(self::wire(['facts' => $ds(16), 'classes' => $ds(8), 'labels' => $ds(16), 'offer_set' => self::d('o')]));
        $this->assertSame("'intent_session.facts' must be an array of at most 16 digests", self::wire(['facts' => $ds(17)]));
        $this->assertSame("'intent_session.classes' must be an array of at most 8 digests", self::wire(['classes' => $ds(9)]));
        $this->assertSame("'intent_session.labels' must be an array of at most 16 digests", self::wire(['labels' => $ds(17)]));
        $this->assertSame("'intent_session.facts' entries must be distinct", self::wire(['facts' => [self::d('a'), self::d('a')]]));
        $this->assertSame("'intent_session.offer_set' is not canonical base64url (32 bytes)", self::wire(['offer_set' => null]));
        $prov = fn(int $n) => array_combine(array_map(fn($i) => "action.params.p$i", range(1, $n)), array_fill(0, $n, ['r']));
        $this->assertNull(self::wire(['prov' => $prov(32)]));
        $this->assertSame("'intent_session.prov' must be an object of at most 32 entries", self::wire(['prov' => $prov(33)]));
        $this->assertSame("'intent_session.prov' key 'env.x' is not action.params.<name>", self::wire(['prov' => ['env.x' => ['r']]]));
        $bad = "'intent_session.prov.action.params.t' must be 1..8 non-empty strings of at most 256 UTF-8 bytes";
        $this->assertNull(self::wire(['prov' => ['action.params.t' => array_fill(0, 8, str_repeat('r', 256))]]));
        $this->assertSame($bad, self::wire(['prov' => ['action.params.t' => array_fill(0, 9, 'r')]]));
        $this->assertSame($bad, self::wire(['prov' => ['action.params.t' => []]]));
        $this->assertSame($bad, self::wire(['prov' => ['action.params.t' => [str_repeat('r', 257)]]]));
        $this->assertSame($bad, self::wire(['prov' => ['action.params.t' => ['']]]));
    }

    public function testWireSlotIsTerminalInVerify(): void
    {
        $g = self::grant();
        $p = self::pcactn($g, self::intentSession(['seq' => -1]));
        $r = self::verify($p, $g, self::ctx());
        $this->assertSame(['wire' => false], $r['checks']);
        $this->assertSame("wire: 'intent_session.seq' must be a safe integer in [0, 2147483647]", $r['reason']);
    }

    // ==== v2 goal + caveat ==============================================================================================

    public function testV2GoalBindsTheSession(): void
    {
        [$g, $p] = self::base();
        $this->assertTrue(self::verify($p, $g, self::ctx())['checks']['intent']);
        $v1 = self::o(['caveats' => [['type' => 'envelope', 'goal_commit' => Pca::intentGoalCommit(self::ref(), self::map0(), self::SALT)]]]);
        $this->assertSame('fail', Pca::decideIntentBinding($p->get('intent'), $v1, null, self::session())['status']);
        $this->assertSame('pass', Pca::decideIntentBinding($p->get('intent'), $v1, null, null)['status']);
        $this->assertSame(Pca::hashCanonical(self::o(['d' => "atlas-pca/goal/v1\0", 'goal' => 'pca-intent:v2:' . self::session() . ':' . self::map0(),
            'salt' => self::SALT])), Pca::intentGoalCommit('ignored', self::map0(), self::SALT, self::session()));
    }

    public function testCaveatSatisfiedIffWellFormed(): void
    {
        $ok = ['type' => 'intent_session', 'session' => self::session(), 'seq' => 0, 'root' => self::d('r')];
        $ctx = self::o(['now' => 1]);
        $this->assertTrue(Pca::evaluateCaveats([self::o($ok)], $ctx)['ok']);
        $this->assertTrue(Pca::evaluateCaveats([self::o(array_merge($ok, ['seq' => 1, 'prev' => self::d('p')]))], $ctx)['ok']);
        foreach ([['seq' => 1], ['prev' => self::d('p')], ['seq' => 2147483648], ['x' => 1], ['root' => 'r'], ['seq' => null]] as $i => $over) {
            $r = Pca::evaluateCaveats([self::o(array_merge($ok, $over))], $ctx);
            $this->assertSame(['ok' => false, 'failed' => ['intent_session']], $r, "case $i");
        }
        $this->assertFalse(Pca::evaluateCaveats([self::o($ok)], self::o([]))['ok']); // needs a finite now
        $this->assertSame('intent_session caveat: prev is present exactly when seq > 0', IntentV2::intentSessionCaveatError(self::o(array_merge($ok, ['prev' => self::d('p')]))));
    }

    // ==== rule 14 =======================================================================================================

    public function testSchemaVerification(): void
    {
        $this->assertSame(['ok' => true], IntentV2::verifyActionSchema(self::schema(), self::keys()));
        $this->assertSame('schema signature invalid', IntentV2::verifyActionSchema(self::schema(), self::keys('stranger'))['reason']);
        $this->assertSame("no schema key with kid 'k1'", IntentV2::verifyActionSchema(self::schema(), [self::o(['kid' => 'k2', 'alg' => 'ed25519', 'pk' => self::pub('site')])])['reason']);
        $this->assertSame('the schema keys must be an array', IntentV2::verifyActionSchema(self::schema(), null)['reason']);
        $this->assertSame('the schema key pq_pk must be a string', IntentV2::verifyActionSchema(self::schema(),
            [self::o(['kid' => 'k1', 'alg' => 'ed25519', 'pk' => self::pub('site'), 'pq_pk' => null])])['reason']);
        $tampered = self::schema();
        $tampered->set('version', 'x');
        $this->assertSame('schema signature invalid', IntentV2::verifyActionSchema($tampered, self::keys())['reason']);
        $this->assertSame("unknown member 'extra'", IntentV2::actionSchemaShapeError(self::o(array_merge(self::unsignedSchema(), ['extra' => 1, 'sig' => []]))));
        $mis = self::schema([], 'site', ['alg' => 'ml-dsa-65']);
        $why = IntentV2::verifyActionSchema($mis, self::keys())['reason'];
        $this->assertTrue($why === 'sig.alg does not match the pinned key suite' || str_contains($why, 'unsupported_suite'), $why);
    }

    public function testSchemaUnsupportedSuite(): void
    {
        $s = self::schema([], 'site', ['alg' => 'no-such-suite']);
        $this->assertSame("sig.alg: unsupported_suite: 'no-such-suite'", IntentV2::actionSchemaShapeError($s));
        $this->assertSame('sig.alg: alg must be a string', IntentV2::actionSchemaShapeError(self::schema([], 'site', ['alg' => null])));
        $this->assertSame('unsupported_suite', Pca::verifyPinnedSuite('no-such-suite', self::pub('site'), null, 'm', 'x', null, null));
        // SLH-DSA is host-dependent (OpenSSL >= 3.5 provides it): unsupported where absent, else refused without a pinned PQ key.
        $this->assertSame(Pca::suiteAvailable('slh-dsa-sha2-128f') ? false : 'unsupported_suite',
            Pca::verifyPinnedSuite('slh-dsa-sha2-128f', self::pub('site'), null, 'm', 'x', null, null));
        $this->assertFalse(Pca::verifyPinnedSuite(5, self::pub('site'), null, 'm', 'x', null, null));
        $msg = 'hello';
        $this->assertTrue(Pca::verifyPinnedSuite(null, self::pub('site'), null, $msg, self::sign('site', $msg), null, null));
        $this->assertTrue(Pca::verifyEd25519B64u(self::pub('site'), $msg, self::sign('site', $msg)));
        $this->assertFalse(Pca::verifyEd25519B64u(self::pub('site'), $msg . 'x', self::sign('site', $msg)));
    }

    public function testSchemaShapeBoundaries(): void
    {
        $p = fn(array $decl) => IntentV2::actionSchemaShapeError(self::schema(['verbs' => [['verb' => 'v', 'kind' => 'read', 'params' => ['action.params.x' => $decl]]]]));
        $base = ['type' => 'integer', 'semantic' => 's', 'sensitivity' => 'free'];
        $this->assertNull($p($base));
        $this->assertSame("verb 'v': action.params.x: default must not be null (absent = no default)", $p($base + ['default' => null]));
        $this->assertSame("verb 'v': action.params.x: min > max", $p($base + ['min' => 2, 'max' => 1]));
        $this->assertNull($p($base + ['min' => 1, 'max' => 1]));
        $this->assertSame("verb 'v': action.params.x: max_len must be a positive safe integer", $p(['type' => 'string'] + $base + ['max_len' => 0]));
        $this->assertSame("verb 'v': action.params.x: semantic must be a non-empty string", $p(['semantic' => str_repeat('s', 129)] + $base));
        $this->assertNull($p(['semantic' => str_repeat('s', 128)] + $base));
        $this->assertSame("verb 'v': action.params.x: accumulates_into must be 1..8 unit ids", $p($base + ['accumulates_into' => array_map(fn($i) => "u$i", range(1, 9))]));
        $this->assertNull($p($base + ['accumulates_into' => array_map(fn($i) => "u$i", range(1, 8))]));
        $this->assertSame("verb 'v': action.params.x: accumulates_into entries must be unit ids", $p($base + ['accumulates_into' => ["u\n"]]));
        foreach (['__proto__', 'constructor', 'prototype'] as $n) {
            $s = self::schema(['verbs' => [['verb' => 'v', 'kind' => 'read', 'params' => ["action.params.$n" => $base]]]]);
            $this->assertSame("verb 'v': parameter name 'action.params.$n' is reserved (__proto__ / constructor / prototype)", IntentV2::actionSchemaShapeError($s));
        }
        $this->assertSame("verb 'v': parameter path 'action.params.x\n' is not action.params.<name>",
            IntentV2::actionSchemaShapeError(self::schema(['verbs' => [['verb' => 'v', 'kind' => 'read', 'params' => ["action.params.x\n" => $base]]]])));
        $this->assertSame("verb 'v' is declared twice", IntentV2::actionSchemaShapeError(self::schema(['verbs' => [
            ['verb' => 'v', 'kind' => 'read', 'params' => (object)[]], ['verb' => 'v', 'kind' => 'read', 'params' => (object)[]]]])));
        $this->assertSame('verbs must be 1..256 entries', IntentV2::actionSchemaShapeError(self::schema(['verbs' => []])));
        $this->assertSame("unit 'usd_cents': exponent must be an integer in [0, 18]", IntentV2::actionSchemaShapeError(self::schema(['units' => ['usd_cents' => ['kind' => 'm', 'exponent' => 19]]])));
        $this->assertNull(IntentV2::actionSchemaShapeError(self::schema(['units' => ['usd_cents' => ['kind' => 'm', 'exponent' => 18]]])));
    }

    public function testConformOrderAndCodes(): void
    {
        $s = self::schema();
        $this->assertTrue(IntentV2::conformAction($s, 'air.book', self::params())['ok']);
        $this->assertSame('params_not_object', IntentV2::conformAction($s, 'air.book', [])['code']);
        $this->assertSame('unknown_verb', IntentV2::conformAction($s, 'air.cancel', self::params())['code']);
        $r = IntentV2::conformAction($s, 'air.book', self::params(['zz' => 1, 'aa' => 1]));
        $this->assertSame(['undeclared_param', 'action.params.aa'], [$r['code'], $r['path']]);
        $r = IntentV2::conformAction($s, 'air.book', self::o(['offer_id' => 'x', 'extra' => 1]));
        $this->assertSame('undeclared_param', $r['code']); // undeclared before missing
        $r = IntentV2::conformAction($s, 'air.book', new Obj());
        $this->assertSame(['missing_param', 'action.params.add_ons'], [$r['code'], $r['path']]);
        $total = fn(mixed $t) => IntentV2::conformAction($s, 'air.book', self::params(['total' => $t]));
        $this->assertTrue($total(5000000)['ok']);
        $this->assertTrue($total(0)['ok']);
        $this->assertSame('out_of_domain', $total(5000001)['code']);
        $this->assertSame('out_of_domain', $total(-1)['code']);
        $this->assertSame('bad_type', $total('38900')['code']);
        $this->assertSame('bad_type', $total(1.5)['code']);
        $neg = self::params();
        $neg->set('total', new Num('-0'));
        $this->assertSame('bad_type', IntentV2::conformAction($s, 'air.book', $neg)['code']);
        $int = self::params();
        $int->set('total', new Num('38900.0'));
        $this->assertTrue(IntentV2::conformAction($s, 'air.book', $int)['ok']);
        $this->assertSame('bad_type', IntentV2::conformAction($s, 'air.book', self::params(['refundable' => 'false']))['code']);
        $this->assertSame('out_of_domain', IntentV2::conformAction($s, 'air.book', self::params(['add_ons' => ['none', 'none']]))['code']);
        $this->assertTrue(IntentV2::conformAction($s, 'air.book', self::params(['add_ons' => []]))['ok']);
        $this->assertSame('bad_type', IntentV2::conformAction($s, 'air.book', self::params(['add_ons' => [1]]))['code']);
        $this->assertTrue(IntentV2::conformAction($s, 'air.book', self::params(['passengers' => array_fill(0, 9, 'p')]))['ok']);
        $this->assertSame('out_of_domain', IntentV2::conformAction($s, 'air.book', self::params(['passengers' => array_fill(0, 10, 'p')]))['code']);
        $this->assertTrue(IntentV2::conformAction($s, 'air.book', self::params(['passengers' => [str_repeat('x', 64)]]))['ok']);
        $this->assertSame('bad_type', IntentV2::conformAction($s, 'air.book', self::params(['passengers' => [str_repeat('x', 65)]]))['code']);
        $this->assertTrue(IntentV2::conformAction($s, 'air.book', self::params(['note' => str_repeat('n', 16)]))['ok']);
        $this->assertSame('out_of_domain', IntentV2::conformAction($s, 'air.book', self::params(['note' => str_repeat('n', 17)]))['code']);
        $search = fn(string $date, string $from = 'SFO', int $pax = 2) => IntentV2::conformAction($s, 'air.search', self::o(['from' => $from, 'date' => $date, 'pax' => $pax]));
        $this->assertTrue($search('2028-02-29')['ok']);
        $this->assertTrue($search('2000-02-29')['ok']);
        $this->assertSame('out_of_domain', $search('2026-02-29')['code']);
        $this->assertSame('out_of_domain', $search('1900-02-29')['code']);
        $this->assertSame('out_of_domain', $search('2026-1-05')['code']);
        $this->assertSame('out_of_domain', $search("2026-01-05\n")['code']);
        $this->assertSame('out_of_domain', $search('0000-01-01')['code']);
        $this->assertSame('out_of_domain', $search('2026-12-31', 'LAX')['code']);
        $this->assertSame('out_of_domain', $search('2026-12-31', 'SFO', 10)['code']);
        $this->assertTrue($search('9999-12-31', 'JFK', 9)['ok']);
    }

    public function testSchemaStepOrder(): void
    {
        [$g, $p] = self::base();
        $r = self::v2($p, $g, self::ctx(['schema' => ['docs' => [self::schema(['version' => 'other'])], 'keys' => self::keys()]]));
        $this->assertSame('intent_session.schema names no schema this verifier accepts', $r['schema']);
        $r = self::v2($p, $g, self::ctx(['schema' => ['docs' => [self::schema()], 'keys' => self::keys('stranger')]]));
        $this->assertSame('schema does not verify: schema signature invalid', $r['schema']);
        $r = self::v2($p, $g, self::ctx(['params' => self::params(['total' => 1])]));
        $this->assertSame('params do not hash to action.params_digest', $r['schema']);
        $this->assertSame('the schema context must be {docs: [...], keys: [...]}', self::v2($p, $g, self::ctx(['schema' => ['docs' => [self::schema()]]]))['schema']);
        $bad = self::params(['total' => 9000000]);
        $g2 = self::grant();
        $p2 = self::pcactn($g2, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 9000000]]]), $bad);
        $this->assertStringStartsWith('schema_violation: out_of_domain: ', self::v2($p2, $g2, self::ctx(['params' => $bad]))['schema']);
        $np = self::ctx();
        $np = $np->without('params');
        $this->assertSame('no plaintext params to check against the schema (closed world needs them)', self::v2($p, $g, $np)['schema']);
    }

    // ==== rule 13 =======================================================================================================

    public function testSessionRootBinding(): void
    {
        [$g, $p] = self::base();
        $noRoot = self::ctx(['session' => ['grants' => []]]);
        $this->assertSame('no session root for this session', self::v2($p, $g, $noRoot)['intent_session']);
        $this->assertSame('no session root for this session', self::v2($p, $g, $noRoot)['accumulators']);
        $exp = self::ctxNow() + 86400000;
        $this->assertSame('the session root has expired', self::v2($p, $g, self::ctx(), $exp)['intent_session']);
        $this->assertTrue(self::v2($p, $g, self::ctx(), $exp - 1)['intent_session']);
        $other = self::ctx(['session' => ['root' => self::root(['question_uri' => 'https://other']), 'grants' => []]]);
        $this->assertSame('intent_session.root is not the digest of the session root', self::v2($p, $g, $other)['intent_session']);
        $forged = self::root();
        $forged->set('question_uri', 'https://forged');
        $this->assertSame('session root: session root signature invalid', self::v2($p, $g, self::ctx(['session' => ['root' => $forged]]))['intent_session']);
    }

    public function testSessionRootShape(): void
    {
        $this->assertNull(IntentV2::sessionRootShapeError(self::root()));
        $this->assertSame('layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)',
            IntentV2::sessionRootShapeError(self::root(['layers' => ['task' => ['map_digest' => self::map0()], 'org' => null]])));
        $this->assertSame('layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)',
            IntentV2::sessionRootShapeError(self::root(['layers' => ['task' => ['map_digest' => self::map0()], 'std' => ['profile' => 'p', 'version' => 0, 'digest' => self::d('s')]]])));
        $this->assertNull(IntentV2::sessionRootShapeError(self::root(['layers' => ['task' => ['map_digest' => self::map0()], 'std' => ['profile' => 'p', 'version' => 1, 'digest' => self::d('s')]]])));
        $this->assertSame('principals must be 1..16 keys', IntentV2::sessionRootShapeError(self::root(['principals' => []])));
        $this->assertSame("principal alg: unsupported_suite: 'zz'", IntentV2::sessionRootShapeError(self::root(['principals' => [['key' => self::pub('principal'), 'alg' => 'zz']]])));
        $this->assertSame('signer is not one of the session principals', IntentV2::sessionRootShapeError(self::root([], 'agent')));
        $this->assertSame('revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)',
            IntentV2::sessionRootShapeError(self::root(['revocation' => ['epoch_uri' => 'u', 'max_age_s' => 60, 'pq_pk' => self::d('q')]])));
        $this->assertSame('revocation.key must not be a session principal (a dedicated revocation authority)',
            IntentV2::sessionRootShapeError(self::root(['revocation' => ['epoch_uri' => 'u', 'max_age_s' => 60, 'key' => self::pub('principal')]])));
        $this->assertNull(IntentV2::sessionRootShapeError(self::root(['revocation' => ['epoch_uri' => 'u', 'max_age_s' => 60, 'key' => self::pub('revoker')]])));
        $this->assertSame('revocation.pq_pk must be canonical base64url',
            IntentV2::sessionRootShapeError(self::root(['revocation' => ['epoch_uri' => 'u', 'max_age_s' => 60, 'key' => self::pub('revoker'), 'pq_pk' => 'x=']])));
        $this->assertSame('accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype',
            IntentV2::sessionRootShapeError(self::root(['accumulators' => [self::trip(['id' => 'constructor'])]])));
        $this->assertSame("accumulator 'trip_spend': key must be null or action.params.<name>",
            IntentV2::sessionRootShapeError(self::root(['accumulators' => [array_diff_key(self::trip(), ['key' => 1])]])));
        $this->assertSame('monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype',
            IntentV2::sessionRootShapeError(self::root(['monitors' => [['id' => '__proto__', 'kind' => 'never', 'p' => ['verb' => 'x']]]])));
        $m = ['id' => 'm', 'kind' => 'responds_within', 'p' => ['verb' => 'x'], 'q' => ['verb' => 'y']];
        $this->assertNull(IntentV2::sessionRootShapeError(self::root(['monitors' => [$m + ['within' => 64]]])));
        $this->assertSame("monitor 'm': within must be an integer in 1..64", IntentV2::sessionRootShapeError(self::root(['monitors' => [$m + ['within' => 65]]])));
        $this->assertSame("monitor 'm': within must be an integer in 1..64", IntentV2::sessionRootShapeError(self::root(['monitors' => [$m + ['within' => 0]]])));
        $this->assertSame(['idle', 'pending:1', 'pending:2', 'missed'], IntentV2::monitorStates(self::o($m + ['within' => 2])));
    }

    public function testSessionBindingSteps(): void
    {
        [$g, $p] = self::base();
        $agentGrant = self::grant(signer: 'agent');
        $pa = self::pcactn($agentGrant, self::intentSession());
        // an agent-signed root fails the chain AND the principal step
        $this->assertSame('the admitting root is not signed by a session principal', self::v2($pa, $agentGrant, self::ctx())['intent_session']);
        $wrongSeq = self::grant(seq: 1, prev: self::d('p'));
        $pw = self::pcactn($wrongSeq, self::intentSession());
        $this->assertSame('the admitting root is bound to another session, root or seq', self::v2($pw, $wrongSeq, self::ctx())['intent_session']);
        $noCav = self::grant(sc: ['type' => 'note']);
        $pn = self::pcactn($noCav, self::intentSession());
        $this->assertSame('admitting root: not an intent_session caveat', self::v2($pn, $noCav, self::ctx())['intent_session']);
        $pm = self::pcactn(self::grant(map: self::d('m1')), self::intentSession(), null, self::d('m1'));
        $this->assertSame('a seq-0 action must use the session task map', self::v2($pm, self::grant(map: self::d('m1')), self::ctx())['intent_session']);
        $noIntent = self::pcactn($g, self::intentSession());
        $noIntent = $noIntent->without('intent');
        $this->assertSame('an intent_session needs the envelope.intent binding', self::v2($noIntent, $g, self::ctx())['intent_session']);
        $this->assertSame('the session grants must be an array', self::v2($p, $g, self::ctx(['session' => ['root' => self::root(), 'grants' => null]]))['intent_session']);
    }

    public function testDeltaChain(): void
    {
        $g0 = self::grant();
        $d1 = self::grant(seq: 1, prev: $g0->get('id'), map: self::d('m1'), salt: 'salt1');
        $is = self::intentSession(['seq' => 1, 'acc' => [['id' => 'trip_spend', 'post' => 77800]]]);
        $p = self::pcactn($d1, $is, null, self::d('m1'));
        $p->set('intent', self::o(['ref' => self::ref(), 'map_digest' => self::d('m1'), 'goal_salt' => 'salt1', 'fidelity_ppm' => 1000000, 'residual_risk_ppm' => 0]));
        $p->set('sig', self::sign('agent', Pca::thresholdMessage($p)));
        $ctx = fn(array $grants) => self::ctx(['session' => ['root' => self::root(), 'grants' => $grants],
            'acc' => ['state' => ['trip_spend' => ['sum' => 38900]], 'monitors' => (object)[]]]);
        $r = self::verify($p, $d1, $ctx([$g0]));
        $this->assertTrue($r['allow'], $r['reason']);
        $this->assertSame('the verifier does not hold the 1 earlier grants of this session', self::v2($p, $d1, $ctx([]))['intent_session']);
        $this->assertSame('session grant 0 is not a capability', self::v2($p, $d1, $ctx(['x']))['intent_session']);
        $other = self::grant(salt: 'other');
        $this->assertSame('the admitting root does not chain to grant 0', self::v2($p, $d1, $ctx([$other]))['intent_session']);
        $alg = self::grant();
        $alg->set('alg', 'zz');
        $this->assertSame("session grant 0: unsupported_suite: 'zz'", self::v2($p, $d1, $ctx([$alg]))['intent_session']);
        $agent0 = self::grant(signer: 'agent');
        $this->assertSame('session grant 0 is not signed by a session principal', self::v2($p, $d1, $ctx([$agent0]))['intent_session']);
    }

    // ---- revocation (dedicated authority, full revoked list, append-only) ----------------------------------------------

    /** revset_root computed in-test: RFC 6962 over SHA-256(0x00 || canonical(id)) leaves, bound to the size. */
    private static function revRoot(array $leaves): string
    {
        $h = array_map(fn($id) => hash('sha256', "\x00" . IntentV2::canonicalize($id), true), $leaves);
        $tree = function (array $hs) use (&$tree): string {
            $n = count($hs);
            if ($n === 1) {
                return $hs[0];
            }
            $k = 1;
            while ($k * 2 < $n) {
                $k *= 2;
            }
            return hash('sha256', "\x01" . $tree(array_slice($hs, 0, $k)) . $tree(array_slice($hs, $k)), true);
        };
        $t = count($h) === 0 ? hash('sha256', '', true) : $tree($h);
        return Pca::b64u(hash('sha256', "pca-revset/v1\0" . IntentV2::canonicalize(Obj::of(['size' => count($leaves), 'tree' => Pca::b64u($t)])), true));
    }

    private const REVOKED = ['pca-intent:map:a', 'pca-intent:session:zzzz'];

    /** A signed epoch over `$revoked` (epoch == set_size == |revoked|) by `$signer`, with `$over` applied BEFORE signing. */
    private static function epoch(array $revoked, array $over = [], string $signer = 'revoker'): array
    {
        $n = count($revoked);
        $body = array_merge(['instance_id' => 'ana', 'grant_ref' => 'pca-intent-session:' . self::session(), 'epoch' => $n, 'set_size' => $n,
            'root' => self::revRoot($revoked), 'issued_at' => self::ctxNow() - 10000, 'not_after' => self::ctxNow() + 290000], $over);
        $sig = self::sign($signer, IntentV2::REVEPOCH_DOMAIN . IntentV2::canonicalize(self::o($body)));
        return $body + ['guardian' => self::pub($signer), 'sig' => $sig];
    }

    private static function evidence(array $revoked = self::REVOKED, array $epochOver = [], string $signer = 'revoker'): Obj
    {
        return self::o(['epoch' => self::epoch($revoked, $epochOver, $signer), 'revoked' => $revoked]);
    }

    private static function rev(mixed $ev, array $c = []): array
    {
        return IntentV2::checkSessionRevocation($ev, array_merge(['session' => self::session(), 'authority' => self::pub('revoker'),
            'ids' => ['pca-intent:session:' . self::session()], 'now' => self::ctxNow(), 'maxAgeMs' => 60000], $c));
    }

    public function testRevocationBoundaries(): void
    {
        $this->assertSame(['ok' => true], self::rev(self::evidence()));
        $this->assertSame(['ok' => true], self::rev(self::evidence([])));
        $this->assertTrue(self::rev(self::evidence(self::REVOKED, ['issued_at' => self::ctxNow() - 60000]))['ok']);
        $this->assertSame('the session revocation epoch is older than 60000 ms', self::rev(self::evidence(self::REVOKED, ['issued_at' => self::ctxNow() - 60001]))['reason']);
        $this->assertTrue(self::rev(self::evidence(self::REVOKED, ['issued_at' => self::ctxNow() + 60000]))['ok']);
        $this->assertSame('revocation epoch issued in the future', self::rev(self::evidence(self::REVOKED, ['issued_at' => self::ctxNow() + 60001]))['reason']);
        $this->assertTrue(self::rev(self::evidence(self::REVOKED, ['not_after' => self::ctxNow()]))['ok']);
        $this->assertSame('revocation epoch expired (stale revocation root)', self::rev(self::evidence(self::REVOKED, ['not_after' => self::ctxNow() - 1]))['reason']);
        $this->assertSame('revocation max age misconfigured (fail closed)', self::rev(self::evidence(), ['maxAgeMs' => -1])['reason']);
        $this->assertTrue(self::rev(self::evidence(self::REVOKED, ['issued_at' => self::ctxNow()]), ['maxAgeMs' => 0])['ok']);
        $this->assertSame('the verifier clock is not a safe integer (fail closed)', self::rev(self::evidence(), ['now' => 1.5])['reason']);
        $this->assertSame('ids must be an array and the authority a key', self::rev(self::evidence(), ['ids' => 'x'])['reason']);
        $this->assertSame('ids must be an array and the authority a key', self::rev(self::evidence(), ['authority' => null])['reason']);
        $this->assertSame('no session revocation epoch supplied', self::rev(null)['reason']);
        $this->assertSame('the revocation epoch must be an object', self::rev(self::o(['epoch' => null, 'revoked' => []]))['reason']);
        $extra = self::evidence();
        $extra->set('proofs', (object)[]);
        $this->assertSame("the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})", self::rev($extra)['reason']);
        $two = self::evidence();
        $two->set('zz', 1);
        $two->set('7', 1);
        $this->assertSame("the revocation evidence has the unknown member '7' (it is exactly {epoch, revoked})", self::rev($two)['reason']); // key order
        // a missing member is not a closed-evidence error: `revoked` fails at the list step (after the signature and age),
        // `epoch` at the epoch shape step
        $this->assertSame('revoked must be an array of ids', self::rev(self::evidence()->without('revoked'))['reason']);
        $this->assertSame('the session revocation epoch is older than 60000 ms',
            self::rev(self::evidence(self::REVOKED, ['issued_at' => self::ctxNow() - 60001])->without('revoked'))['reason']);
        $this->assertSame('the revocation epoch must be an object', self::rev(new Obj())['reason']);
        // only the dedicated authority signs: a principal's (validly signed) epoch is refused
        $this->assertSame('the revocation epoch is not signed by the session revocation authority', self::rev(self::evidence(self::REVOKED, [], 'principal'))['reason']);
        $tampered = self::evidence();
        $tampered->get('epoch')->set('instance_id', 'bob');
        $this->assertSame('revocation epoch signature invalid', self::rev($tampered)['reason']);
        $this->assertSame('revocation epoch is for a different grant', self::rev(self::evidence(self::REVOKED, ['grant_ref' => 'pca-intent-session:' . self::d('s2')]))['reason']);
        $this->assertTrue(self::rev(self::evidence(self::REVOKED, ['grant_ref' => 'scope-x']), ['scope' => 'scope-x'])['ok']);
        // the id itself is revoked; a non-string id
        $this->assertSame("'pca-intent:map:a' is revoked", self::rev(self::evidence(), ['ids' => ['pca-intent:map:a']])['reason']);
        $this->assertSame("'5' is revoked", self::rev(self::evidence(), ['ids' => [5]])['reason']);
        $str = self::evidence();
        $str->get('epoch')->set('set_size', '2');
        $this->assertSame('revocation epoch set_size must be a non-negative safe integer', self::rev($str)['reason']);
        $nullAlg = self::evidence();
        $nullAlg->get('epoch')->set('alg', null);
        $this->assertSame('revocation epoch alg: alg must be a string', self::rev($nullAlg)['reason']);
        $pq = self::evidence();
        $pq->get('epoch')->set('alg', 'no-such-suite');
        $this->assertStringContainsString('unsupported_suite', self::rev($pq)['reason']);
    }

    public function testRevokedListIsTheSignedSet(): void
    {
        $l = fn(mixed $revoked, array $epochOver = []) => self::rev(self::o(['epoch' => self::epoch(self::REVOKED, $epochOver), 'revoked' => $revoked]))['reason'] ?? 'ok';
        $this->assertSame('revoked must be an array of ids', $l(null));
        $this->assertSame('revoked must be an array of ids', $l('pca-intent:map:a'));
        $this->assertSame('revoked must be an array of ids', $l(['pca-intent:map:a', 5]));
        $this->assertSame('revoked must be sorted by UTF-8 bytes and distinct', $l(array_reverse(self::REVOKED)));
        $this->assertSame('revoked must be sorted by UTF-8 bytes and distinct', $l(['pca-intent:map:a', 'pca-intent:map:a']));
        $this->assertSame('the epoch must be numbered by its set size and list exactly set_size ids', $l(['pca-intent:map:a']));
        $this->assertSame('the epoch must be numbered by its set size and list exactly set_size ids', $l(self::REVOKED, ['epoch' => 3]));
        $this->assertSame('the revoked list is not the signed set (root mismatch)', $l(['pca-intent:map:a', 'pca-intent:session:zzzy']));
        $this->assertSame(self::revRoot(self::REVOKED), IntentV2::revsetRoot(self::REVOKED));
        $this->assertSame(self::revRoot([]), IntentV2::revsetRoot([]));
        $three = ['a', 'b', 'c'];
        $this->assertSame(self::revRoot($three), IntentV2::revsetRoot($three));
    }

    public function testRevocationAppendOnly(): void
    {
        $more = ['pca-intent:map:a', 'pca-intent:map:b', 'pca-intent:session:zzzz'];
        $last = self::evidence();
        $this->assertTrue(self::rev(self::evidence(), ['last' => $last])['ok']);                // same epoch, same root
        $this->assertTrue(self::rev(self::evidence($more), ['last' => $last])['ok']);           // superset, later epoch
        $this->assertSame('revocation epoch rollback (older than the last accepted)', self::rev(self::evidence(), ['last' => self::evidence($more)])['reason']);
        $drop = ['pca-intent:map:b', 'pca-intent:session:zzzz'];
        $this->assertSame("the epoch drops 'pca-intent:map:a', revoked in the last accepted epoch (not append-only)",
            self::rev(self::evidence($drop), ['last' => $last])['reason']);
        $dropLarger = ['pca-intent:map:b', 'pca-intent:map:c', 'pca-intent:session:zzzz'];
        $this->assertSame("the epoch drops 'pca-intent:map:a', revoked in the last accepted epoch (not append-only)",
            self::rev(self::evidence($dropLarger), ['last' => $last])['reason']);
        // same epoch number, another set: the drop check refuses it before equivocation is reached (with verified full lists a
        // superset of equal size is the same set, so equivocation is only reachable through a malformed list, refused earlier)
        $other = ['pca-intent:map:a', 'pca-intent:session:zzzy'];
        $this->assertSame("the epoch drops 'pca-intent:session:zzzy', revoked in the last accepted epoch (not append-only)",
            self::rev(self::evidence(), ['last' => self::evidence($other)])['reason']);
        $bad = self::o(['epoch' => self::epoch(self::REVOKED), 'revoked' => ['pca-intent:map:a']]);
        $this->assertSame('the tracked last epoch is malformed (fail closed)', self::rev(self::evidence(), ['last' => $bad])['reason']);
        $this->assertSame('the tracked last epoch is malformed (fail closed)', self::rev(self::evidence(), ['last' => null])['reason']);
        $extraLast = self::evidence();
        $extraLast->set('note', 'x');
        $this->assertSame('the tracked last epoch is malformed (fail closed)', self::rev(self::evidence(), ['last' => $extraLast])['reason']);
        $this->assertSame('the tracked last epoch is malformed (fail closed)', self::rev(self::evidence(), ['last' => self::evidence()->without('revoked')])['reason']);
    }

    public function testSessionRevocationInPipeline(): void
    {
        $revBlock = ['epoch_uri' => 'https://e', 'max_age_s' => 60, 'key' => self::pub('revoker')];
        $S = self::root(['revocation' => $revBlock]);
        $gS = self::grant(S: $S);
        $pS = self::pcactn($gS, self::intentSession([], $S));
        $ctx = fn(mixed $ev, array $pol = [], mixed $last = null) => self::ctx(['session' => array_merge(['root' => $S, 'grants' => []],
            $ev !== null ? ['revocation' => $ev] : [], $last !== null ? ['revocation_last' => $last] : []), 'policy' => $pol ?: (object)[]]);
        $this->assertSame('revocation: no session revocation epoch supplied', self::v2($pS, $gS, $ctx(null))['intent_session']);
        $this->assertTrue(self::v2($pS, $gS, $ctx(self::evidence()))['intent_session']);
        // the admitting delta id revoked
        $revokedDelta = ['pca-intent:delta:' . $gS->get('id'), 'pca-intent:map:a'];
        sort($revokedDelta, SORT_STRING);
        $this->assertSame("revocation: 'pca-intent:delta:" . $gS->get('id') . "' is revoked", self::v2($pS, $gS, $ctx(self::evidence($revokedDelta)))['intent_session']);
        // the stricter of S.revocation.max_age_s (60 s) and the policy applies: 9 s < 10 s old
        $this->assertSame('revocation: the session revocation epoch is older than 9000 ms',
            self::v2($pS, $gS, $ctx(self::evidence(), ['session' => ['max_revocation_age_s' => 9]]))['intent_session']);
        // tracked last epoch (append-only) through the context
        $more = ['pca-intent:map:a', 'pca-intent:map:b', 'pca-intent:session:zzzz'];
        $this->assertSame('revocation: revocation epoch rollback (older than the last accepted)',
            self::v2($pS, $gS, $ctx(self::evidence(), [], self::evidence($more)))['intent_session']);
        $this->assertSame('the tracked last revocation epoch must be an object',
            self::v2($pS, $gS, self::ctx(['session' => ['root' => $S, 'revocation_last' => null]]))['intent_session']);
        // a principal's epoch is refused; a policy age with no authority in S fails
        $this->assertSame('revocation: the revocation epoch is not signed by the session revocation authority',
            self::v2($pS, $gS, $ctx(self::evidence(self::REVOKED, [], 'principal')))['intent_session']);
        [$g, $p] = self::base();
        $this->assertSame('revocation: the policy requires a revocation epoch but the session root names no revocation authority',
            self::v2($p, $g, self::ctx(['policy' => ['session' => ['max_revocation_age_s' => 60]]]))['intent_session']);
    }

    // ==== rule 15 =======================================================================================================

    public function testSiteLocalAccumulators(): void
    {
        [$g, $p] = self::base();
        $st = fn(mixed $state) => self::ctx(['acc' => ['state' => ['trip_spend' => $state], 'monitors' => (object)[]]]);
        $this->assertTrue(self::v2($p, $g, $st(['sum' => 0]))['accumulators']);
        $this->assertSame("claimed post 38900 for 'trip_spend' differs from the verifier's 38901", self::v2($p, $g, $st(['sum' => 1]))['accumulators']);
        $this->assertSame("accumulator 'trip_spend': pre-state of a sum accumulator is {sum}", self::v2($p, $g, $st(['count' => 0]))['accumulators']);
        $this->assertSame("accumulator 'trip_spend': pre-state sum must be a non-negative safe integer", self::v2($p, $g, $st(['sum' => '0']))['accumulators']);
        $this->assertSame("accumulator 'trip_spend': pre-state sum must be a non-negative safe integer", self::v2($p, $g, $st(['sum' => null]))['accumulators']);
        $this->assertSame("no state for site-local accumulator 'trip_spend'", self::v2($p, $g, self::ctx(['acc' => ['state' => (object)[]]]))['accumulators']);
        $this->assertSame("no state for site-local accumulator 'trip_spend'", self::v2($p, $g, self::ctx(['acc' => (object)[]]))['accumulators']);
        // domain_max 500000 inclusive
        $at = fn(int $pre, int $post) => (function () use ($pre, $post) {
            $g = self::grant();
            $p = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => $post]]]));
            return self::v2($p, $g, self::ctx(['acc' => ['state' => ['trip_spend' => ['sum' => $pre]]]]))['accumulators'];
        })();
        $this->assertTrue($at(500000 - 38900, 500000));
        $this->assertSame("accumulator 'trip_spend' post 500001 is outside its domain (max 500000)", $at(500001 - 38900, 500001));
        $this->assertSame("accumulator 'trip_spend' overflows 2^53-1", $at(self::MAX_SAFE, 0));
        // a receipt on a site-local claim, a claim for no accumulator, a wallet claim
        $pr = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => self::d('r')]]]));
        $this->assertSame("accumulator 'trip_spend' is site-local: a receipt is not accepted", self::v2($pr, $g, self::ctx())['accumulators']);
        $pn = self::pcactn($g, self::intentSession(['acc' => [['id' => 'nope', 'post' => 1]]]));
        $this->assertSame("claim 'nope' names no accumulator of the session", self::v2($pn, $g, self::ctx())['accumulators']);
        $pw = self::pcactn($g, self::intentSession(['acc' => [['id' => 'questions', 'post' => 1]]]));
        $this->assertSame("accumulator 'questions' is wallet-held and cannot be claimed at a site", self::v2($pw, $g, self::ctx())['accumulators']);
        $pc = self::pcactn($g, self::intentSession(['acc' => []]));
        $this->assertSame("no claim for accumulator 'trip_spend' that this action feeds", self::v2($pc, $g, self::ctx())['accumulators']);
    }

    public function testWbEnvIsAddedToTheEnvAlreadyBuilt(): void
    {
        // r9: the W-B stage adds its env members to the env the schema step already built (it does not start a new one)
        $g = self::grant();
        $p = self::pcactn($g, self::intentSession(['prov' => ['action.params.offer_id' => ['ref:offer']]]));
        $ctx = self::ctx(['wb' => ['policy' => ['provenance' => ['params' => ['action.params.offer_id' => 'critical'],
            'registry' => ['ref:offer' => 'first_party']]]]]);
        $out = IntentV2::decideIntentV2($p, $g, $ctx, self::ctxNow());
        $this->assertSame(['schema' => true, 'intent_session' => true, 'accumulators' => true, 'provenance' => true], self::v2($p, $g, $ctx));
        $this->assertSame('{"acc":{"trip_spend":{"post":38900}},"canon":{"add_ons":"[\\"none\\"]","refundable":"false"},"mon":{},"prov":{"action":{"params":{"offer_id":"first_party"}}}}',
            Json::canonicalizeStrict($out['env']));
    }

    // ==== r9 fault injection: the internal-error catches ================================================================

    private const LONE = "a\xED\xA0\x80"; // WTF-8 lone high surrogate: a string strict canonical JSON refuses

    public function testSessionRootBindingFaultIsMalformed(): void
    {
        if (!Pca::suiteAvailable('hybrid-ed25519-ml-dsa-65')) {
            $this->markTestSkipped('the hybrid suite is not available on this host (the fault sits behind its binding)');
        }
        $pq = rtrim(strtr(base64_encode(str_repeat("\x05", 1952)), '+/', '-_'), '=');
        $S = self::root(['alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => $pq]);
        $S->set('pq_pk', self::LONE); // not part of the shape check's body; the suite binding canonicalizes it and throws
        $pins = self::o([self::pub('principal') => 'x']);
        $pins->set(self::pub('principal'), self::LONE);
        $this->assertSame(['ok' => false, 'reason' => 'malformed session root: canonicalize: lone surrogate in string'],
            IntentV2::verifySessionRoot($S, $pins));
    }

    public function testKeySetBindingFaultIsUnverified(): void
    {
        if (!Pca::suiteAvailable('hybrid-ed25519-ml-dsa-65')) {
            $this->markTestSkipped('the hybrid suite is not available on this host (the fault sits behind its binding)');
        }
        // a hybrid key set without pq_pk passes the shape check; binding the suite then throws: not verified, never accepted
        $ks = self::keySet([], 'seq-root', ['alg' => 'hybrid-ed25519-ml-dsa-65']);
        $this->assertNull(IntentV2::sequencerKeySetShapeError($ks));
        $this->assertFalse(IntentV2::verifySequencerKeySet($ks, self::pub('seq-root')));
    }

    public function testRevocationFaultFailsClosedWithItsMessage(): void
    {
        $ev = self::evidence(['pca-intent:map:a']);
        $ev->set('revoked', [self::LONE]); // same count as the signed set: the revset root is computed and the canonical form throws
        $this->assertSame(['ok' => false, 'reason' => 'session revocation check error (fail closed): lone surrogate in string'],
            self::rev($ev));
    }

    public function testPerCheckInternalErrorIsReportedWithItsMessage(): void
    {
        $cs = json_decode((string) gzdecode((string) file_get_contents(__DIR__ . '/../test-data/k042-intentv2-cases.json.gz')), true, 512, JSON_THROW_ON_ERROR)['cases'];
        foreach ($cs as $c) {
            if ($c['name'] === 'vec/session-g0') {
                $cs = $c;
                break;
            }
        }
        $p = Json::parseLax($cs['p']);
        $g = Json::parseLax($cs['grant']);
        $ctx = Json::parseLax($cs['ctx']);
        $p->get('intent_session')->set('acc', 1.5); // a host float where a list is read: PHP raises a warning
        set_error_handler(static function (int $no, string $str, string $file, int $line): never {
            throw new \ErrorException($str, 0, $no, $file, $line); // a host error handler that turns warnings into exceptions
        });
        try {
            $out = IntentV2::decideIntentV2($p, $g, $ctx, (int) $cs['now']);
        } finally {
            restore_error_handler();
        }
        $this->assertSame([
            ['name' => 'schema', 'ok' => true],
            ['name' => 'intent_session', 'ok' => true],
            ['name' => 'accumulators', 'ok' => false, 'reason' => 'accumulators error (fail closed): foreach() argument must be of type array|object, float given'],
        ], $out['checks']);
    }

    public function testWalletAccumulatorDoesNotEndTheScan(): void
    {
        // r9: a wallet-held accumulator is skipped, and the accumulators after it are still judged
        $S = self::root(['accumulators' => [self::questions(), self::trip()]]);
        $g = self::grant(S: $S);
        $p = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900]]], $S));
        $r = self::v2($p, $g, self::ctx(['session' => ['root' => $S, 'grants' => []], 'acc' => (object)[]]));
        $this->assertSame("no state for site-local accumulator 'trip_spend'", $r['accumulators']);
    }

    public function testAccumulatorValuesAndCombination(): void
    {
        $sum = self::o(self::trip());
        $schema = self::schema();
        $this->assertSame(['ok' => true, 'val' => 38900], IntentV2::accValueOf($sum, 'air.book', self::params(), $schema));
        $this->assertSame(['action.params.total'], IntentV2::accumulationParams(IntentV2::schemaVerb($schema, 'air.book'), self::UNIT));
        $this->assertTrue(IntentV2::accSelects($sum, 'air.book', $schema));
        $this->assertFalse(IntentV2::accSelects($sum, 'air.search', $schema));
        $this->assertFalse(IntentV2::accSelects($sum, 'air.book', null));
        $dist = self::o(self::trip(['agg' => 'distinct', 'val' => 'action.params.offer_id', 'sel' => ['verbs' => ['air.book']]]));
        $this->assertSame('"OF-1"', IntentV2::accValueOf($dist, 'air.book', self::params(), null)['key']);
        $pre = self::o(['values' => ['"OF-1"']]);
        $this->assertSame(1, IntentV2::combineAcc($dist, $pre, IntentV2::accValueOf($dist, 'air.book', self::params(), null)));
        $this->assertSame(2, IntentV2::combineAcc($dist, $pre, IntentV2::accValueOf($dist, 'air.book', self::params(['offer_id' => 'OF-2']), null)));
        $this->assertSame('pre-state values must be distinct', IntentV2::preStateError($dist, self::o(['values' => ['a', 'a']])));
        $max = self::o(self::trip(['agg' => 'max', 'val' => 'action.params.total', 'sel' => ['verbs' => ['air.book']]]));
        $this->assertSame(38900, IntentV2::combineAcc($max, self::o(['max' => 38899]), ['val' => 38900]));
        $this->assertSame(40000, IntentV2::combineAcc($max, self::o(['max' => 40000]), ['val' => 38900]));
        $cnt = self::o(self::trip(['agg' => 'count', 'sel' => ['verbs' => ['air.book']]]));
        $this->assertSame(['ok' => true, 'val' => 1], IntentV2::accValueOf($cnt, 'air.book', self::params(), null));
        $this->assertSame(8, IntentV2::combineAcc($cnt, self::o(['count' => 7]), ['val' => 1]));
        $neg = self::params();
        $neg->set('total', new Num('-0'));
        $this->assertFalse(IntentV2::accValueOf($max, 'air.book', $neg, null)['ok']);
        $this->assertSame('accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype', IntentV2::accumulatorDeclError(self::o(self::trip(['id' => 'prototype']))));
        $this->assertSame("accumulator 'trip_spend': win sliding needs a positive ms", IntentV2::accumulatorDeclError(self::o(self::trip(['win' => ['kind' => 'sliding', 'ms' => 0]]))));
        $this->assertNull(IntentV2::accumulatorDeclError(self::o(self::trip(['win' => ['kind' => 'period', 'ms' => 1, 't0' => 0]]))));
        $this->assertSame("accumulator 'trip_spend': win period needs a positive ms and t0 >= 0", IntentV2::accumulatorDeclError(self::o(self::trip(['win' => ['kind' => 'period', 'ms' => 1, 't0' => -1]]))));
        $this->assertSame("accumulator 'trip_spend': count takes no val", IntentV2::accumulatorDeclError(self::o(self::trip(['agg' => 'count', 'val' => 'action.params.total']))));
    }

    public function testKeyedAccumulatorAndMonitors(): void
    {
        $keyed = self::trip(['id' => 'per_offer', 'agg' => 'count', 'sel' => ['verbs' => ['air.book']], 'key' => 'action.params.offer_id', 'domain_max' => 3]);
        $S = self::root(['accumulators' => [self::trip(), $keyed], 'monitors' => [['id' => 'm1', 'kind' => 'never', 'p' => ['verb' => 'air.cancel']]]]);
        $g = self::grant(S: $S);
        $p = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900], ['id' => 'per_offer', 'post' => 3]]], $S));
        $ctx = fn(mixed $mon, int $pre = 2) => self::ctx(['session' => ['root' => $S, 'grants' => []],
            'acc' => ['state' => ['trip_spend' => ['sum' => 0], 'per_offer' => ['count' => $pre]], 'monitors' => $mon]]);
        $this->assertTrue(self::v2($p, $g, $ctx(['m1' => 'clean']))['accumulators']);
        $this->assertTrue(self::v2($p, $g, $ctx(['m1' => 'seen']))['accumulators']);
        $this->assertSame("no valid state for monitor 'm1'", self::v2($p, $g, $ctx(['m1' => 'met']))['accumulators']);
        $this->assertSame("no valid state for monitor 'm1'", self::v2($p, $g, $ctx((object)[]))['accumulators']);
        $this->assertSame("accumulator 'per_offer' post 4 is outside its domain (max 3)", self::v2($p, $g, $ctx(['m1' => 'clean'], 3))['accumulators']);
        $d = IntentV2::decideIntentV2($p, $g, $ctx(['m1' => 'clean']), self::ctxNow());
        $this->assertSame('clean', $d['env']->get('mon')->get('m1')->get('state'));
        // the key must be a schema-declared identity, not free text
        $byNote = self::trip(['id' => 'per_note', 'agg' => 'count', 'sel' => ['verbs' => ['air.book']], 'key' => 'action.params.note']);
        $S2 = self::root(['accumulators' => [self::trip(), $byNote]]);
        $g2 = self::grant(S: $S2);
        $params = self::params(['note' => 'hi']);
        $p2 = self::pcactn($g2, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900], ['id' => 'per_note', 'post' => 1]]], $S2), $params);
        $c2 = self::ctx(['params' => $params, 'session' => ['root' => $S2, 'grants' => []], 'acc' => ['state' => ['trip_spend' => ['sum' => 0], 'per_note' => ['count' => 0]]]]);
        $this->assertSame("accumulator 'per_note': the key must be a schema-declared identity (not free text)", self::v2($p2, $g2, $c2)['accumulators']);
        $p3 = self::pcactn($g2, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900], ['id' => 'per_note', 'post' => 1]]], $S2));
        $this->assertSame("accumulator 'per_note': the key parameter action.params.note is missing", self::v2($p3, $g2, self::ctx(['session' => ['root' => $S2, 'grants' => []],
            'acc' => ['state' => ['trip_spend' => ['sum' => 0], 'per_note' => ['count' => 0]]]]))['accumulators']);
    }

    // ---- sequenced holder ---------------------------------------------------------------------------------------------

    private static function keySet(array $keysOver = [], string $rootSigner = 'seq-root', array $setOver = []): Obj
    {
        $ks = self::o(array_merge(['v' => 1, 'kind' => 'pca-sequencer-keys', 'sequencer' => self::pub($rootSigner), 'version' => 3,
            'issued_at' => self::ctxNow() - 100000,
            'keys' => [array_merge(['kid' => 's1', 'pk' => self::pub('seq-1'), 'not_before' => self::ctxNow() - 100000], $keysOver)]], $setOver));
        $ks->set('sig', self::sign($rootSigner, IntentV2::SEQUENCER_KEYS_DOMAIN . IntentV2::canonicalize($ks)));
        return $ks;
    }

    private static function receipt(Obj $p, array $over = [], string $signer = 'seq-1'): Obj
    {
        $r = self::o(array_merge(['v' => 1, 'kind' => 'pca-acc-receipt', 'session' => self::session(), 'acc' => 'trip_spend', 'seq' => 5,
            'pre' => 0, 'delta' => 38900, 'post' => 38900, 'pcactn_digest' => IntentV2::pcactnReservationDigest($p), 'aud' => self::aud(),
            'issued_at' => self::ctxNow() - 1000, 'expires_at' => self::ctxNow() + 60000, 'kid' => 's1',
            'ledger' => ['index' => 4, 'head' => self::d('head')], 'signer' => self::pub($signer)], $over));
        $r->set('sig', self::sign($signer, IntentV2::ACC_RECEIPT_DOMAIN . IntentV2::canonicalize($r)));
        return $r;
    }

    public function testSequencedReceipts(): void
    {
        $S = self::root(['accumulators' => [self::trip(['holder' => ['kind' => 'sequenced', 'uri' => 'https://seq', 'root' => self::pub('seq-root')]])]]);
        $g = self::grant(S: $S);
        $unsigned = self::pcactn($g, self::intentSession([], $S));
        $rc = self::receipt($unsigned);
        $is = self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => IntentV2::accReceiptDigest($rc)]]], $S);
        $p = self::pcactn($g, $is);
        $this->assertSame(IntentV2::pcactnReservationDigest($unsigned), IntentV2::pcactnReservationDigest($p)); // intent_session excluded
        $ctx = fn(array $acc) => self::ctx(['session' => ['root' => $S, 'grants' => []], 'acc' => $acc]);
        $ok = ['receipts' => [$rc], 'sequencer_keys' => [self::keySet()]];
        $r = self::verify($p, $g, $ctx($ok));
        $this->assertTrue($r['allow'], $r['reason']);
        $this->assertTrue(self::v2($p, $g, $ctx($ok + ['last_seq' => ['trip_spend' => 4]]))['accumulators']);
        $this->assertSame("the reservation receipt for 'trip_spend' replays seq 5 (last accepted 5)", self::v2($p, $g, $ctx($ok + ['last_seq' => ['trip_spend' => 5]]))['accumulators']);
        $this->assertSame('acc.last_seq values must be non-negative safe integers',
            self::v2($p, $g, $ctx($ok + ['last_seq' => ['trip_spend' => null]]))['accumulators']);
        $this->assertSame('acc.receipts must be an array', self::v2($p, $g, $ctx(['receipts' => null]))['accumulators']);
        $this->assertSame("the reservation receipt for 'trip_spend' was not presented", self::v2($p, $g, $ctx(['sequencer_keys' => [self::keySet()]]))['accumulators']);
        $notSigned = "the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set lists for its issue time";
        $this->assertSame($notSigned, self::v2($p, $g, $ctx(['receipts' => [$rc]]))['accumulators']);
        $this->assertSame($notSigned, self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet([], 'stranger')]]))['accumulators']);
        // key validity window: issued_at - 1000 must lie in [not_before, not_after]
        $this->assertTrue(self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet(['not_before' => self::ctxNow() - 1000])]]))['accumulators']);
        $this->assertSame($notSigned, self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet(['not_before' => self::ctxNow() - 999])]]))['accumulators']);
        $this->assertTrue(self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet(['not_after' => self::ctxNow() - 1000])]]))['accumulators']);
        $this->assertSame($notSigned, self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet(['not_after' => self::ctxNow() - 1001])]]))['accumulators']);
        // an unsupported suite in the key set surfaces as unsupported_suite
        $this->assertStringContainsString('unsupported_suite', self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet(['alg' => 'zz'])]]))['accumulators']);
        $this->assertSame("the reservation receipt for 'trip_spend': " . IntentV2::UNSUPPORTED_SUITE
            . ' (the receipt or the sequencer key set names a suite this verifier does not implement)',
            self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => [self::keySet(['alg' => 'zz'])]]))['accumulators']);
        // receipt issued beyond the 60 s skew; expired receipt (expires_at inclusive)
        $late = self::receipt($unsigned, ['issued_at' => self::ctxNow() + 60001, 'expires_at' => self::ctxNow() + 120000]);
        $pl = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => IntentV2::accReceiptDigest($late)]]], $S));
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($late, self::o(['root' => self::pub('seq-root')]), [self::keySet(['not_before' => 0])], self::ctxNow()));
        $this->assertSame($notSigned, self::v2($pl, $g, $ctx(['receipts' => [$late], 'sequencer_keys' => [self::keySet(['not_before' => 0])]]))['accumulators']);
        $edge = self::receipt($unsigned, ['expires_at' => self::ctxNow()]);
        $pe = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => IntentV2::accReceiptDigest($edge)]]], $S));
        $this->assertTrue(self::v2($pe, $g, $ctx(['receipts' => [$edge], 'sequencer_keys' => [self::keySet()]]))['accumulators']);
        $gone = self::receipt($unsigned, ['expires_at' => self::ctxNow() - 1]);
        $pg = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => IntentV2::accReceiptDigest($gone)]]], $S));
        $this->assertSame("the reservation receipt for 'trip_spend' has expired", self::v2($pg, $g, $ctx(['receipts' => [$gone], 'sequencer_keys' => [self::keySet()]]))['accumulators']);
        $arith = self::receipt($unsigned, ['post' => 38901]);
        $pa = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38901, 'receipt' => IntentV2::accReceiptDigest($arith)]]], $S));
        $this->assertSame("the reservation receipt for 'trip_spend' does not add up", self::v2($pa, $g, $ctx(['receipts' => [$arith], 'sequencer_keys' => [self::keySet()]]))['accumulators']);
        $noRc = self::pcactn($g, self::intentSession([], $S));
        $this->assertSame("accumulator 'trip_spend' is sequenced: the claim needs a reservation receipt", self::v2($noRc, $g, $ctx($ok))['accumulators']);
        $this->assertTrue(IntentV2::receiptArithmeticOk(self::o(['agg' => 'distinct']), self::o(['pre' => 2, 'delta' => 0, 'post' => 2]), 1));
        $this->assertFalse(IntentV2::receiptArithmeticOk(self::o(['agg' => 'distinct']), self::o(['pre' => 2, 'delta' => 2, 'post' => 4]), 1));
        $this->assertTrue(IntentV2::receiptArithmeticOk(self::o(['agg' => 'max']), self::o(['pre' => 9, 'delta' => 5, 'post' => 9]), 5));
        $this->assertFalse(IntentV2::receiptArithmeticOk(self::o(['agg' => 'count']), self::o(['pre' => 1, 'delta' => 1, 'post' => 3]), 1));
    }

    public function testReceiptAndKeySetShapes(): void
    {
        [$g, $p] = self::base();
        $this->assertNull(IntentV2::accReceiptShapeError(self::receipt($p)));
        $this->assertSame('receipt.seq must be a safe integer >= 1', IntentV2::accReceiptShapeError(self::receipt($p, ['seq' => 0])));
        $this->assertSame('receipt.kid must match [A-Za-z0-9_.:-]{1,64}', IntentV2::accReceiptShapeError(self::receipt($p, ['kid' => str_repeat('k', 65)])));
        $this->assertSame("receipt.alg: unsupported_suite: 'zz'", IntentV2::accReceiptShapeError(self::receipt($p, ['alg' => 'zz'])));
        $this->assertSame('receipt.ledger must be {index, head}', IntentV2::accReceiptShapeError(self::receipt($p, ['ledger' => ['index' => 1]])));
        $this->assertSame('receipt.expires_at must be within 900000 ms after issued_at',
            IntentV2::accReceiptShapeError(self::receipt($p, ['expires_at' => self::ctxNow() - 1000 + 900001])));
        $this->assertNull(IntentV2::accReceiptShapeError(self::receipt($p, ['expires_at' => self::ctxNow() - 1000 + 900000])));
        $this->assertSame('receipt.expires_at must be within 900000 ms after issued_at',
            IntentV2::accReceiptShapeError(self::receipt($p, ['expires_at' => self::ctxNow() - 1001])));
        $this->assertNull(IntentV2::accReceiptShapeError(self::receipt($p, ['expires_at' => self::ctxNow() - 1000])));
        $this->assertSame('version must be a safe integer >= 1', IntentV2::sequencerKeySetShapeError(self::keySet([], 'seq-root', ['version' => 0])));
        $this->assertSame("key set: unknown member 'x'", IntentV2::sequencerKeySetShapeError(self::keySet([], 'seq-root', ['x' => 1])));
        $this->assertSame('key validity must be 0 <= not_before <= not_after', IntentV2::sequencerKeySetShapeError(self::keySet(['not_after' => self::ctxNow() - 100001])));
        $this->assertNull(IntentV2::sequencerKeySetShapeError(self::keySet(['not_after' => self::ctxNow() - 100000])));
        $this->assertTrue(IntentV2::verifySequencerKeySet(self::keySet(), self::pub('seq-root')));
        $this->assertFalse(IntentV2::verifySequencerKeySet(self::keySet(), self::pub('agent')));
    }

    // ---- rule 15 freshness: receipt age, key-set version / age, retired keys (5e718f47) ---------------------------------

    /** A sequenced fixture: [S, grant, the reservation PCActn, ctx(acc, policy)]. */
    private static function seqFixture(): array
    {
        $S = self::root(['accumulators' => [self::trip(['holder' => ['kind' => 'sequenced', 'uri' => 'https://seq', 'root' => self::pub('seq-root')]])]]);
        $g = self::grant(S: $S);
        $unsigned = self::pcactn($g, self::intentSession([], $S));
        $ctx = fn(array $acc, array $pol = []) => self::ctx(['session' => ['root' => $S, 'grants' => []], 'acc' => $acc, 'policy' => $pol ?: (object)[]]);
        return [$S, $g, $unsigned, $ctx];
    }

    /** The `accumulators` verdict for receipt `$rc` under the given key sets / extra acc context / policy. */
    private static function seqVerdict(Obj $rc, array $sets, array $acc = [], array $pol = []): mixed
    {
        [$S, $g, , $ctx] = self::seqFixture();
        $p = self::pcactn($g, self::intentSession(['acc' => [['id' => 'trip_spend', 'post' => 38900, 'receipt' => IntentV2::accReceiptDigest($rc)]]], $S));
        return self::v2($p, $g, $ctx(['receipts' => [$rc], 'sequencer_keys' => $sets] + $acc, $pol))['accumulators'];
    }

    public function testReceiptFreshnessAndKeySets(): void
    {
        [, , $unsigned] = self::seqFixture();
        $notSigned = "the reservation receipt for 'trip_spend' is not signed by a key the session sequencer's root-signed key set lists for its issue time";
        $now = self::ctxNow();
        $rc = self::receipt($unsigned);                                    // issued now - 1000
        $this->assertTrue(self::seqVerdict($rc, [self::keySet()]));
        // receipt age vs policy.acc.max_receipt_age_s (inclusive), default 900 s
        $this->assertTrue(self::seqVerdict($rc, [self::keySet()], [], ['acc' => ['max_receipt_age_s' => 1]]));
        $old = self::receipt($unsigned, ['issued_at' => $now - 1001, 'expires_at' => $now + 1000]);
        $this->assertSame($notSigned, self::seqVerdict($old, [self::keySet()], [], ['acc' => ['max_receipt_age_s' => 1]]));
        $edge = self::receipt($unsigned, ['issued_at' => $now - 900000, 'expires_at' => $now]);
        $this->assertTrue(self::seqVerdict($edge, [self::keySet(['not_before' => $now - 900000])]));
        $over = self::receipt($unsigned, ['issued_at' => $now - 900001, 'expires_at' => $now - 1]);
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($over, self::o(['root' => self::pub('seq-root')]),
            [self::keySet(['not_before' => 0])], $now));
        // the tracked key set acc.keyset_versions[root] = {version, digest}: no rollback, no equivocation at an equal version
        $root = self::pub('seq-root');
        $ks3 = self::keySet();
        $ks4 = self::keySet([], 'seq-root', ['version' => 4]);
        $this->assertSame(IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/sequencer-keys-ref/v1', 'k' => $ks3])), IntentV2::sequencerKeySetDigest($ks3));
        $this->assertTrue(self::seqVerdict($rc, [$ks3], ['keyset_versions' => [$root => ['version' => 3, 'digest' => IntentV2::sequencerKeySetDigest($ks3)]]]));
        $this->assertTrue(self::seqVerdict($rc, [$ks4], ['keyset_versions' => [$root => ['version' => 3, 'digest' => IntentV2::sequencerKeySetDigest($ks3)]]])); // newer
        $this->assertSame($notSigned, self::seqVerdict($rc, [$ks3], ['keyset_versions' => [$root => ['version' => 4, 'digest' => IntentV2::sequencerKeySetDigest($ks4)]]])); // rollback
        $other3 = self::keySet(['kid' => 's1', 'not_before' => self::ctxNow() - 99999]); // another set under version 3
        $this->assertSame($notSigned, self::seqVerdict($rc, [$other3], ['keyset_versions' => [$root => ['version' => 3, 'digest' => IntentV2::sequencerKeySetDigest($ks3)]]])); // equivocation
        $this->assertTrue(self::seqVerdict($rc, [$other3, $ks3], ['keyset_versions' => [$root => ['version' => 3, 'digest' => IntentV2::sequencerKeySetDigest($ks3)]]]));
        $this->assertTrue(self::seqVerdict($rc, [$ks3], ['keyset_versions' => [self::pub('other') => ['version' => 9, 'digest' => self::d('x')]]]));
        foreach ([
            [3, 'a tracked key set must be an object {version, digest}'],
            [null, 'a tracked key set must be an object {version, digest}'],
            [['version' => 3], 'a tracked key set digest must be canonical base64url (32 bytes)'],
            [['version' => 3, 'digest' => 'abc'], 'a tracked key set digest must be canonical base64url (32 bytes)'],
            [['version' => 0, 'digest' => self::d('x')], 'a tracked key set version must be a safe integer >= 1'],
            [['version' => '3', 'digest' => self::d('x')], 'a tracked key set version must be a safe integer >= 1'],
            [['version' => 3, 'digest' => self::d('x'), 'x' => 1], "a tracked key set has the unknown member 'x'"],
        ] as $i => [$bad, $why]) {
            $this->assertSame("acc.keyset_versions: $why", self::seqVerdict($rc, [$ks3], ['keyset_versions' => [$root => $bad]]), "case $i");
        }
        // key-set age (default 3600 s, inclusive) and a future key set (60 s skew, inclusive)
        $this->assertTrue(self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now - 3600000])]));
        $this->assertSame($notSigned, self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now - 3600001])]));
        $this->assertTrue(self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now + 60000])]));
        $this->assertSame($notSigned, self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now + 60001])]));
        $this->assertSame($notSigned, self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now - 2])], [],
            ['acc' => ['max_keyset_age_s' => 0]]));
        // r9: the key-set age bound is in SECONDS (x 1000), inclusive
        $this->assertTrue(self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now - 1000])], [],
            ['acc' => ['max_keyset_age_s' => 1]]));
        $this->assertSame($notSigned, self::seqVerdict($rc, [self::keySet(['not_before' => 0], 'seq-root', ['issued_at' => $now - 1001])], [],
            ['acc' => ['max_keyset_age_s' => 1]]));
        // a RETIRED key (not_after < now - 60 s) stops verifying even for a receipt issued inside its window
        $back = self::receipt($unsigned, ['issued_at' => $now - 70000, 'expires_at' => $now + 1000]);
        $this->assertTrue(self::seqVerdict($back, [self::keySet(['not_after' => $now - 60000])]));
        $this->assertSame($notSigned, self::seqVerdict($back, [self::keySet(['not_after' => $now - 60001])]));
        // bounds and the key-set list are typed
        $holder = self::o(['root' => $root]);
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now, -1));
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], 1.5));
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, 'x', $now));
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now, null, null, null, self::o(['version' => 3])));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now, null, null, 3));
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now, null, null, 4));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now));
        // r9: an invalid minimum key set version is refused, not ignored
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now, null, null, -1));
        $this->assertSame('invalid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet()], $now, null, null, 1.5));
        // r9: a key set that fails any admission test is SKIPPED, and the next one is still tried
        $good = self::keySet();
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet([], 'not-the-root'), $good], $now));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet([], 'seq-root', ['version' => 2]), $good], $now, null, null, 3));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet(['kid' => 'other']), $good], $now));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet(['not_after' => $now - 60001]), $good], $now));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet(['pk' => self::pub('seq-2')]), $good], $now));
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet(['not_before' => $now]), $good], $now));
        $pqpk = rtrim(strtr(base64_encode(str_repeat("\x05", 1952)), '+/', '-_'), '=');
        $this->assertSame('valid', IntentV2::verifyReceiptAgainstHolder($rc, $holder, [self::keySet(['alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => $pqpk]), $good], $now)); // suite mismatch
    }

    public function testReceiptArithmeticAndPublicHelpers(): void
    {
        $r = fn(int $pre, int $delta, int $post) => self::o(['pre' => $pre, 'delta' => $delta, 'post' => $post]);
        $agg = fn(string $a) => self::o(['agg' => $a]);
        $this->assertTrue(IntentV2::receiptArithmeticOk($agg('sum'), $r(5, 3, 8), 3));
        $this->assertFalse(IntentV2::receiptArithmeticOk($agg('sum'), $r(5, 3, 9), 3));
        $this->assertTrue(IntentV2::receiptArithmeticOk($agg('count'), $r(5, 1, 6), 99));
        $this->assertFalse(IntentV2::receiptArithmeticOk($agg('count'), $r(5, 2, 7), 2));
        $this->assertTrue(IntentV2::receiptArithmeticOk($agg('max'), $r(5, 3, 5), 3));
        $this->assertTrue(IntentV2::receiptArithmeticOk($agg('max'), $r(5, 7, 7), 7));
        $this->assertFalse(IntentV2::receiptArithmeticOk($agg('max'), $r(5, 7, 12), 7));
        $this->assertTrue(IntentV2::receiptArithmeticOk($agg('distinct'), $r(5, 0, 5), 1));
        $this->assertTrue(IntentV2::receiptArithmeticOk($agg('distinct'), $r(5, 1, 6), 1));
        $this->assertFalse(IntentV2::receiptArithmeticOk($agg('distinct'), $r(5, 2, 7), 1));
        $this->assertFalse(IntentV2::receiptArithmeticOk($agg('bogus'), $r(5, 1, 6), 1));
        $this->assertFalse(IntentV2::receiptArithmeticOk(self::o([]), $r(5, 1, 6), 1));
        foreach (['distinctKey', 'revocationEpochShapeError', 'checkRevocationEpoch', 'sessionRevocationId', 'sessionRevocationScope',
            'grantSessionCaveat', 'accSelects'] as $m) {
            $this->assertTrue((new \ReflectionMethod(IntentV2::class, $m))->isPublic(), $m);
        }
        // accSelects is total on a PCActn-less accumulator (no selector object at all)
        $this->assertFalse(IntentV2::accSelects(self::o([]), 'v', null));
        $this->assertFalse(IntentV2::accSelects(self::o(['sel' => 5]), 'v', null));
    }

    public function testPolicyAccAndMapAreClosedAndTyped(): void
    {
        [$g, $p] = self::base();
        foreach ([
            [['acc' => ['max_receipt_age_s' => null]], 'policy.acc.max_receipt_age_s must be a non-negative safe integer'],
            [['acc' => ['max_keyset_age_s' => '60']], 'policy.acc.max_keyset_age_s must be a non-negative safe integer'],
            [['acc' => ['x' => 1]], "policy.acc: unknown member 'x'"],
            [['acc' => null], 'policy.acc must be an object'],
            [['map' => ['require' => 'yes']], 'policy.map.require must be a boolean'],
            [['map' => ['max_residual_risk_ppm' => -1]], 'policy.map.max_residual_risk_ppm must be a non-negative safe integer'],
            [['map' => ['x' => 1]], "policy.map: unknown member 'x'"],
            [['map' => []], 'policy.map must be an object'],
        ] as $i => [$pol, $why]) {
            $this->assertSame("malformed v2 context: $why", self::v2($p, $g, self::ctx(['policy' => $pol]))['schema'], "case $i");
        }
        $this->assertSame("malformed v2 context: map: unknown member 'x'", self::v2($p, $g, self::ctx(['map' => ['x' => 1]]))['schema']);
        $this->assertSame('malformed v2 context: map must be an object', self::v2($p, $g, self::ctx(['map' => null]))['schema']);
        $this->assertNull(IntentV2::intentV2ContextError(self::o(['policy' => ['acc' => ['max_receipt_age_s' => 0, 'max_keyset_age_s' => 0],
            'map' => ['require' => false, 'max_residual_risk_ppm' => 0]], 'map' => (object)[]])));
    }

    // ==== rule 19: the committed map =====================================================================================

    private const MAP_METRICS = ['residual_risk_ppm' => 1200, 'burden_ppm' => 3, 'uncertainty_ppm' => 4, 'disagreement_ppm' => 0,
        'mean_harm_ppm' => 10, 'fidelity_est_ppm' => 990000, 'entropy_mbits' => 12, 'questions' => 2, 'conflicts' => 0];

    private static function mapHeader(): array
    {
        return ['verb' => 'air.book', 'first' => 1, 'cells' => 9, 'dims' => [
            ['kind' => 'num', 'path' => 'action.params.total', 'lo' => 0, 'hi' => 100000, 'cuts' => [40000]],
            ['kind' => 'cat', 'path' => 'action.resource', 'values' => [['kind' => 'exact', 'value' => 'skyair.example/bookings'],
                ['kind' => 'prefix', 'value' => 'skyair.example/'], ['kind' => 'other', 'value' => "\u{22A5}"]]],
        ]];
    }

    /** The committed map built in-test: [map_commit, leaves [kind, leaf Obj, salt], leaf hashes]. */
    private static function committedMap(array $metrics = self::MAP_METRICS): array
    {
        $leaves = [['header', self::o(self::mapHeader())]];
        for ($f = 0; $f < 9; $f++) {
            $cell = [intdiv($f, 3), $f % 3];
            $leaves[] = ['cell', self::o(['verb' => 'air.book', 'cell' => $cell, 'p_ppm' => 1000 + $f, 'in_grant' => $cell[0] === 0 && $cell[1] < 2])];
        }
        $leaves[] = ['metrics', self::o($metrics)];
        $leaves[] = ['learner', self::o(['learner_digest' => self::d('learner')])];
        $hashes = [];
        foreach ($leaves as $i => [$kind, $leaf]) {
            $salt = hash('sha256', "kill-map-salt/$i", true);
            $leaves[$i][2] = $salt;
            $hashes[] = IntentV2::mapLeafHash($kind, $salt, $leaf);
        }
        return [IntentV2::mapCommitOf(count($hashes), self::treeRoot($hashes)), $leaves, $hashes];
    }

    private static function treeRoot(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = 1;
        while ($k * 2 < count($hs)) {
            $k *= 2;
        }
        return hash('sha256', IntentV2::MAP_TAG_NODE . self::treeRoot(array_slice($hs, 0, $k)) . self::treeRoot(array_slice($hs, $k)), true);
    }

    /** RFC 9162 audit path of leaf `$i` (bottom-up), computed in-test. */
    private static function auditPath(array $hs, int $i): array
    {
        if (count($hs) === 1) {
            return [];
        }
        $k = 1;
        while ($k * 2 < count($hs)) {
            $k *= 2;
        }
        return $i < $k ? [...self::auditPath(array_slice($hs, 0, $k), $i), self::treeRoot(array_slice($hs, $k))]
            : [...self::auditPath(array_slice($hs, $k), $i - $k), self::treeRoot(array_slice($hs, 0, $k))];
    }

    private static function entry(array $map, int $i): array
    {
        [, $leaves, $hashes] = $map;
        return ['index' => $i, 'salt' => Pca::b64u($leaves[$i][2]), 'leaf' => $leaves[$i][1], 'path' => array_map([Pca::class, 'b64u'], self::auditPath($hashes, $i))];
    }

    private static function disclosure(array $map, int $cellFlat = 0): Obj
    {
        return self::o(['size' => count($map[1]), 'header' => self::entry($map, 0), 'cell' => self::entry($map, 1 + $cellFlat), 'metrics' => self::entry($map, 10)]);
    }

    /** decideMapDisclosure over the in-test map for `$params` / `$resource`. */
    private static function mapDecide(array $map, Obj $disc, ?Obj $params = null, string $resource = 'skyair.example/bookings', mixed $eps = null): array
    {
        $params ??= self::params();
        $action = self::o(['verb' => 'air.book', 'resource' => $resource, 'params_digest' => IntentV2::hashCanonical($params)]);
        return IntentV2::decideMapDisclosure($map[0], $action, $params, $disc, $eps);
    }

    public function testMapCommitmentAndDisclosure(): void
    {
        $map = self::committedMap();
        $this->assertSame($map[0], IntentV2::mapCommitOfLeaves(array_map(fn($l) => self::o(['kind' => $l[0], 'salt' => Pca::b64u($l[2]), 'leaf' => $l[1]]), $map[1])));
        $ok = self::mapDecide($map, self::disclosure($map));
        $this->assertSame([0, 0], $ok['cell'], $ok['reason'] ?? '');
        $this->assertSame(1000, $ok['p_ppm']);
        $this->assertSame(1200, $ok['residual_risk_ppm']);
        // the exact cell of omega: num cells [0, 39999], {40000}, [40001, 100000]; cat exact > longest prefix > other
        $total = fn(int $t) => self::params(['total' => $t]);
        $this->assertTrue(self::mapDecide($map, self::disclosure($map, 0), $total(39999))['ok']);
        $this->assertSame("the action's cell is outside the committed grant", self::mapDecide($map, self::disclosure($map, 3), $total(40000))['reason']);
        $this->assertSame("the disclosed cell is not the action's cell", self::mapDecide($map, self::disclosure($map, 0), $total(40000))['reason']);
        $this->assertSame("the action's cell is outside the committed grant", self::mapDecide($map, self::disclosure($map, 6), $total(40001))['reason']);
        $this->assertSame("the action's cell is outside the committed grant", self::mapDecide($map, self::disclosure($map, 6), $total(100000))['reason']);
        $this->assertSame("the action's action.params.total lies outside the committed map's dimension", self::mapDecide($map, self::disclosure($map), $total(100001))['reason']);
        // -0 is not a safe integer for the cell lookup (mapCellOf; TS isSafeInt). Through decideMapDisclosure it never gets that far:
        // the params digest refuses -0 first (strict canonical form, TS strictNumberError 'negative zero'), so it fails closed there.
        $neg = self::params();
        $neg->set('total', new Num('-0'));
        $header = $map[1][0][1];
        $this->assertSame(['error' => "the action's action.params.total lies outside the committed map's dimension"],
            IntentV2::mapCellOf($header, 'skyair.example/bookings', $neg));
        $this->assertSame([0, 0], IntentV2::mapCellOf($header, 'skyair.example/bookings', self::params(['total' => 0]))['cell']);
        $action = self::o(['verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'params_digest' => IntentV2::hashCanonical(self::params(['total' => 0]))]);
        $r = IntentV2::decideMapDisclosure($map[0], $action, $neg, self::disclosure($map));
        $this->assertFalse($r['ok']);
        $this->assertSame('map error (fail closed): canonicalize: negative zero', $r['reason']);
        $this->assertTrue(self::mapDecide($map, self::disclosure($map, 1), null, 'skyair.example/other')['ok']);   // prefix
        $this->assertSame("the action's cell is outside the committed grant", self::mapDecide($map, self::disclosure($map, 2), null, 'elsewhere')['reason']); // other
        // eps (inclusive)
        $this->assertTrue(self::mapDecide($map, self::disclosure($map), null, 'skyair.example/bookings', 1200)['ok']);
        $this->assertSame("the committed residual risk 1200 ppm exceeds \u{03B5} = 1199", self::mapDecide($map, self::disclosure($map), null, 'skyair.example/bookings', 1199)['reason']);
        // openings: a salt, a leaf, a path element, the size, a missing / extra path hash
        $d = self::disclosure($map);
        $d->get('header')->set('salt', self::d('other'));
        $this->assertSame('the header leaf does not open the map commitment', self::mapDecide($map, $d)['reason']);
        $d = self::disclosure($map);
        $d->get('cell')->get('leaf')->set('p_ppm', new Num('1001'));
        $this->assertSame('the cell leaf does not open the map commitment', self::mapDecide($map, $d)['reason']);
        $d = self::disclosure($map);
        $d->set('size', new Num('13'));
        $this->assertSame('the header leaf does not open the map commitment', self::mapDecide($map, $d)['reason']);
        $d = self::disclosure($map);
        $path = $d->get('metrics')->get('path');
        $d->get('metrics')->set('path', [...$path, $path[0]]);
        $this->assertSame('the metrics leaf does not open the map commitment', self::mapDecide($map, $d)['reason']);
        // metrics position, layout, verb
        $d = self::disclosure($map);
        $d->set('metrics', self::o(self::entry($map, 11)));
        $this->assertStringStartsWith('map disclosure malformed: ', self::mapDecide($map, $d)['reason']); // the learner leaf is no metrics leaf
        $other = self::o(['verb' => 'air.search', 'resource' => 'x', 'params_digest' => IntentV2::hashCanonical(self::params())]);
        $this->assertSame("the disclosed header is not the action's verb", IntentV2::decideMapDisclosure($map[0], $other, self::params(), self::disclosure($map))['reason']);
        $this->assertSame('the params do not hash to action.params_digest',
            IntentV2::decideMapDisclosure($map[0], self::o(['verb' => 'air.book', 'params_digest' => self::d('x')]), self::params(), self::disclosure($map))['reason']);
        $this->assertSame('params must be an object', IntentV2::decideMapDisclosure($map[0], self::o([]), [], self::disclosure($map))['reason']);
        $this->assertSame('the PCActn carries no map commitment', IntentV2::decideMapDisclosure('x', self::o([]), IntentV2::undef(), self::disclosure($map))['reason']);
        $this->assertSame('map disclosure malformed: the disclosure must be exactly {size, header, cell, metrics}', IntentV2::decideMapDisclosure($map[0], self::o([]), IntentV2::undef(), null)['reason']);
        $d = self::disclosure($map);
        $d->set('size', new Num('3'));
        $this->assertSame('map disclosure malformed: disclosure.size must be a safe integer in [4, 16777216]', self::mapDecide($map, $d)['reason']);
        $d = self::disclosure($map);
        $d->get('cell')->set('path', array_fill(0, 65, self::d('h')));
        $this->assertSame('map disclosure malformed: disclosure.cell.path must be an array of 32-byte digests', self::mapDecide($map, $d)['reason']);
        $this->assertNull(IntentV2::mapRootFromPath(0, 12, $map[2][0], []));
        $this->assertNull(IntentV2::mapRootFromPath(12, 12, $map[2][0], []));
    }

    public function testMapLeafShapes(): void
    {
        $h = self::mapHeader();
        $this->assertNull(IntentV2::mapHeaderError(self::o($h)));
        $bad = function (callable $f) use ($h) {
            $x = $h;
            $f($x);
            return IntentV2::mapHeaderError(self::o($x));
        };
        $this->assertSame("header.cells is not the product of the dimensions' cell counts", $bad(function (&$x) { $x['cells'] = 8; }));
        $this->assertSame('header.dims[0].cuts must be strictly increasing safe integers in [lo, hi]', $bad(function (&$x) { $x['dims'][0]['cuts'] = [40000, 40000]; }));
        $this->assertSame('header.dims[0].cuts must be strictly increasing safe integers in [lo, hi]', $bad(function (&$x) { $x['dims'][0]['cuts'] = [100001]; }));
        $this->assertSame('header.dims[0] lo / hi must be safe integers with lo <= hi', $bad(function (&$x) { $x['dims'][0]['lo'] = 100001; }));
        $this->assertSame('header.dims[0].path must be action.params.<name>', $bad(function (&$x) { $x['dims'][0]['path'] = 'action.resource'; }));
        $this->assertSame("header.dims[1].values: exactly one other ('\u{22A5}'), last; prefixes non-empty", $bad(function (&$x) { $x['dims'][1]['values'][1]['value'] = ''; }));
        $this->assertSame('header.dims[1].values must end with the other value', $bad(function (&$x) { array_pop($x['dims'][1]['values']); }));
        $this->assertSame("header.dims[1].values: exactly one other ('\u{22A5}'), last; prefixes non-empty", $bad(function (&$x) { $x['dims'][1]['values'][2]['value'] = 'x'; }));
        $this->assertSame('header.dims[1].values must be distinct', $bad(function (&$x) { $x['dims'][1]['values'][1] = $x['dims'][1]['values'][0]; }));
        $this->assertSame('header.dims[1].kind must be num or cat', $bad(function (&$x) { $x['dims'][1]['kind'] = 'enum'; }));
        $this->assertSame('header.dims paths must be distinct', $bad(function (&$x) { $x['dims'][1]['path'] = 'action.params.total'; }));
        $this->assertSame('header.first must be a leaf index', $bad(function (&$x) { $x['first'] = 16777216; }));
        $this->assertSame('the header leaf must be exactly {verb, first, cells, dims}', $bad(function (&$x) { $x['x'] = 1; }));
        $this->assertSame('cell.p_ppm must be a safe integer in [0, 1000000]', IntentV2::mapCellError(self::o(['verb' => 'v', 'cell' => [0], 'p_ppm' => 1000001, 'in_grant' => true])));
        $this->assertSame('cell.in_grant must be a boolean', IntentV2::mapCellError(self::o(['verb' => 'v', 'cell' => [0], 'p_ppm' => 1, 'in_grant' => 1])));
        $this->assertNull(IntentV2::mapMetricsError(self::o(self::MAP_METRICS)));
        $this->assertNull(IntentV2::mapMetricsError(self::o(self::MAP_METRICS + ['log2_vs_mbits' => 0])));
        $this->assertSame('metrics.log2_vs_mbits must be a non-negative safe integer', IntentV2::mapMetricsError(self::o(self::MAP_METRICS + ['log2_vs_mbits' => null])));
        $this->assertSame('learner.learner_digest must be canonical base64url (32 bytes)', IntentV2::mapLearnerError(self::o(['learner_digest' => 'x'])));
    }

    public function testMapCheckInThePipeline(): void
    {
        $map = self::committedMap();
        $S = self::root(['layers' => ['task' => ['map_digest' => $map[0]]]]);
        $g = self::grant(S: $S, map: $map[0], mapForm: 'commit');
        $p = self::pcactn($g, self::intentSession(['map_form' => 'commit'], $S), null, $map[0]);
        $ctx = fn(mixed $disc, array $pol = []) => self::ctx(['session' => ['root' => $S, 'grants' => []], 'policy' => $pol ?: (object)[]]
            + ($disc !== null ? ['map' => ['disclosure' => $disc]] : []));
        $r = self::verify($p, $g, $ctx(self::disclosure($map)));
        $this->assertTrue($r['allow'], $r['reason']);
        $this->assertSame([...self::CORE, 'intent', 'schema', 'intent_session', 'accumulators', 'map'], array_keys($r['checks']));
        $this->assertSame('no disclosure of the committed map was presented', self::v2($p, $g, $ctx(null))['map']);
        $this->assertSame("the committed residual risk 1200 ppm exceeds \u{03B5} = 1199",
            self::v2($p, $g, $ctx(self::disclosure($map), ['map' => ['max_residual_risk_ppm' => 1199]]))['map']);
        // the v2c goal: a grant over the plain v2 goal never opens under the commit form
        $plain = self::grant(S: $S, map: $map[0]);
        $pp = self::pcactn($plain, self::intentSession(['map_form' => 'commit'], $S), null, $map[0]);
        $this->assertFalse(self::verify($pp, $plain, $ctx(self::disclosure($map)))['checks']['intent']);
        $this->assertNotSame(Pca::intentGoalCommit('r', $map[0], 's', self::session()), Pca::intentGoalCommit('r', $map[0], 's', self::session(), 'commit'));
        $this->assertSame(Pca::hashCanonical(self::o(['d' => "atlas-pca/goal/v1\0", 'goal' => 'pca-intent:v2c:' . self::session() . ':' . $map[0], 'salt' => 's'])),
            Pca::intentGoalCommit('ignored', $map[0], 's', self::session(), 'commit'));
        // policy.map.require: reported even without intent_session, and a plain-form PCActn fails it
        [$g0, $p0] = self::base();
        $this->assertSame(['map' => 'this verifier requires a committed map (intent_session.map_form "commit")'],
            self::v2(self::pcactn($g0, null), $g0, self::ctx(['policy' => ['map' => ['require' => true]]])));
        $this->assertSame('this verifier requires a committed map (intent_session.map_form "commit")',
            self::v2($p0, $g0, self::ctx(['policy' => ['map' => ['require' => true]]]))['map']);
        $this->assertTrue(IntentV2::intentV2Active(self::pcactn($g0, null), self::ctx(['policy' => ['map' => ['require' => true]]])));
        // a malformed context fails map too (only with the commit form)
        $this->assertSame(['schema', 'intent_session', 'accumulators', 'map'], array_keys(self::v2($p, $g, self::ctx(['params' => null]))));
        $this->assertSame(['schema', 'intent_session', 'accumulators'], array_keys(self::v2($p0, $g0, self::ctx(['params' => null]))));
        // wire: map_form must be "commit" when present
        $this->assertNull(IntentV2::validateIntentSessionWire(self::o(self::intentSession(['map_form' => 'commit']))));
        foreach (['plain', null, true] as $i => $bad) {
            $this->assertSame("'intent_session.map_form' must be \"commit\" when present", IntentV2::validateIntentSessionWire(self::o(self::intentSession(['map_form' => $bad]))), "case $i");
        }
    }

    public function testPrimitiveRunnerPrefersInputJson(): void
    {
        $schema = self::schema();
        $text = '{"schema":' . IntentV2::canonicalize($schema) . ',"keys":' . IntentV2::canonicalize(self::keys())
            . ',"verb":"air.book","params":{"offer_id":"OF-1","total":-0,"add_ons":["none"],"refundable":false}}';
        $want = self::o(['sig' => true, 'digest' => IntentV2::actionSchemaDigest($schema),
            'conform' => ['ok' => false, 'code' => 'bad_type', 'path' => 'action.params.total']]);
        // the lossy `input` copy (-0 written as 0) would conform; `input_json` keeps negative zero and must win
        $lossy = self::o(['schema' => $schema, 'keys' => self::keys(), 'verb' => 'air.book', 'params' => self::params(['total' => 0])]);
        $prim = Obj::of(['intent_schema' => [Obj::of(['name' => 'neg-zero', 'input' => $lossy, 'input_json' => $text, 'expect' => $want])]]);
        $fails = [];
        $counts = Corpus::runIntentPrimitives($prim, function (bool $ok, string $msg) use (&$fails): void {
            if (!$ok) {
                $fails[] = $msg;
            }
        });
        $this->assertSame([], $fails);
        $this->assertSame(1, $counts['intent_schema']['ran']);
        // intent_revocation: the evidence is the input minus the check parameters, so an extra input member is malformed
        $in = self::o(['epoch' => self::epoch(self::REVOKED), 'revoked' => self::REVOKED, 'session' => self::session(), 'authority' => self::pub('revoker'),
            'ids' => ['pca-intent:session:' . self::session()], 'now' => self::ctxNow(), 'max_age_ms' => 60000]);
        [$ok, $why] = IntentV2::primitive('intent_revocation', $in);
        $this->assertTrue($ok->get('ok'), (string)$why);
        $in->set('proofs', (object)[]);
        [$bad, $why] = IntentV2::primitive('intent_revocation', $in);
        $this->assertFalse($bad->get('ok'));
        $this->assertSame("the revocation evidence has the unknown member 'proofs' (it is exactly {epoch, revoked})", $why);
        $this->assertTrue($counts['intent_map']['absent']);
        [$got] = IntentV2::primitive('intent_schema', Json::parseLax($text));
        $this->assertSame(IntentV2::canonicalize($want), IntentV2::canonicalize($got));
        $this->assertNull(IntentV2::primitive('intent_nope', new Obj()));
    }

    // ==== W-B totality (45a1599e) ========================================================================================

    public function testWbEntryPointsNeverThrow(): void
    {
        foreach ([null, 5, 'x', [], true] as $i => $bad) {
            $wb = \Atlas\Pca\IntentWb::decideIntentWb($bad);
            $this->assertSame('deny', $wb['outcome'], "case $i");
            $this->assertSame(['facts' => 'fail'], $wb['checks'], "case $i");
            $this->assertSame('facts: the W-B context is malformed: input must be an object', $wb['reason'], "case $i");
            $this->assertSame(['ok' => false, 'reason' => 'facts: input must be an object'], \Atlas\Pca\IntentWb::decideIntentWorld($bad), "case $i");
            $this->assertSame('provenance: input must be an object', \Atlas\Pca\IntentWb::decideParamProvenance($bad)['reason'], "case $i");
            $this->assertSame(['ok' => false, 'reason' => 'classes: input must be an object'], \Atlas\Pca\IntentWb::decideClassifierDimensions($bad), "case $i");
            $this->assertSame('input must be an object', \Atlas\Pca\IntentWb::intentWbContextError($bad), "case $i");
            $this->assertSame('artifact must be an object', \Atlas\Pca\IntentWb::artifactSuiteError($bad), "case $i");
        }
        $this->assertNull(\Atlas\Pca\IntentWb::flowRuleFor(null, 'pii'));
        $this->assertNull(\Atlas\Pca\IntentWb::flowRuleFor(new Obj(), 5));
        $this->assertFalse(\Atlas\Pca\IntentWb::flowAllowed(new Obj(), 5, 'a', 'a'));
        $this->assertFalse(\Atlas\Pca\IntentWb::flowAllowed(new Obj(), 'pii', null, null));
        $this->assertNull(\Atlas\Pca\IntentWb::parseLabelRef(5));
        $this->assertNull(\Atlas\Pca\IntentWb::ratioPpm(1.5, 2));
        $this->assertNull(\Atlas\Pca\IntentWb::ratioPpm(1, 0));
        $this->assertSame(500000, \Atlas\Pca\IntentWb::ratioPpm(1, 2));
        $this->assertFalse(\Atlas\Pca\IntentWb::offerMatches(null, new Obj()));
        $this->assertFalse(\Atlas\Pca\IntentWb::queryCovers(new Obj(), 'x'));
        // the pipeline turns any W-B refusal into a failed `facts` check, never an exception
        [$g, $p] = self::base();
        $r = self::v2($p, $g, self::ctx(['wb' => ['policy' => ['world' => ['worlds' => ['x']]]]]));
        $this->assertIsString($r['facts']);
    }

    // ==== middleware =====================================================================================================

    private static function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public bool $called = false;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;
                return new Response(200);
            }
        };
    }

    private static function middleware(mixed $intentV2, Obj $grant): PcaMiddleware
    {
        $f = new HttpFactory();
        return new PcaMiddleware(self::aud(), fn(string $ref) => $ref === $grant->get('id') ? $grant : null, fn(): int => self::ctxNow(),
            $f, $f, 'pca', null, $intentV2);
    }

    private static function request(Obj $p): ServerRequestInterface
    {
        return new ServerRequest('POST', '/x', ['PCA-Action' => Pca::b64u(Json::canonicalizeStrict($p))]);
    }

    public function testMiddlewareIntentV2Sources(): void
    {
        [$g, $p] = self::base();
        $h = self::handler();
        $this->assertSame(200, self::middleware(self::ctx(), $g)->process(self::request($p), $h)->getStatusCode());
        $this->assertTrue($h->called);
        $seen = null;
        $h = self::handler();
        $res = self::middleware(function (Obj $pc) use (&$seen) {
            $seen = $pc;
            return self::ctx();
        }, $g)->process(self::request($p), $h);
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame($p->get('grant_ref'), $seen->get('grant_ref'));
        foreach ([fn() => throw new \RuntimeException('store down'), fn() => 'not an obj'] as $i => $bad) {
            $h = self::handler();
            $res = self::middleware($bad, $g)->process(self::request($p), $h);
            $this->assertSame(403, $res->getStatusCode(), "case $i");
            $this->assertFalse($h->called);
            $body = json_decode((string)$res->getBody(), true);
            $this->assertSame('intent_v2_context_error', $body['error']);
            $this->assertArrayNotHasKey('checks', $body);
        }
        // without the verifier state the v2 checks fail closed (403 with the verdict)
        $h = self::handler();
        $res = self::middleware(fn() => null, $g)->process(self::request($p), $h);
        $this->assertSame(403, $res->getStatusCode());
        $this->assertFalse(json_decode((string)$res->getBody(), true)['checks']['schema']);
        $this->expectException(\InvalidArgumentException::class);
        self::middleware('not callable at all', $g);
    }
}
