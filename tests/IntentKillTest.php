<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Mutation-kill tests (Infection) for the Intent Layer M2 `envelope.intent` code paths of src/Pca.php:
 * validateIntentWire, intentGoal / intentGoalCommit, intentPolicyActive (+ intentPolicyMap), intentThreshold,
 * rootGoalCommit, decideIntentBinding and the `intent` check of verifyPcactnCore / verifyJson. Every boundary is pinned on
 * both sides and every reason is asserted exactly, so an off-by-one, negated or deleted-branch mutant dies.
 */
final class IntentKillTest extends TestCase
{
    private const SALT = 'c2FsdC1pbnRlbnQ';
    private const MAX_SAFE = 9007199254740991;
    private const REQ = 'this verifier requires an intent binding but the PCActn carries none';
    private const MIS = 'intent policy misconfigured: thresholds must be non-negative safe integers (fail closed)';
    private const NOENV = 'the root grant carries no envelope goal commitment to bind the intent to';
    private const OPEN = "intent ref / map_digest / goal_salt do not open the root grant's goal commitment";
    private const ERR = 'intent binding error (fail closed): ';
    private const BASE = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion',
        'leaf_signature', 'counter'];

    // ---- fixtures ---------------------------------------------------------------------------------------------------

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION));
    }

    /** @return array{0:string,1:string} [public b64u, secret key] */
    private static function key(string $name): array
    {
        $keys = json_decode(file_get_contents(Corpus::DIR . 'keys.json'), true);
        $kp = sodium_crypto_sign_seed_keypair(Pca::unb64u($keys[$name]['seed']));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), sodium_crypto_sign_secretkey($kp)];
    }

    private static function sign(string $name, string $msg): string
    {
        return Pca::b64u(sodium_crypto_sign_detached($msg, self::key($name)[1]));
    }

    private static function d(string $label): string
    {
        return Pca::b64u(hash('sha256', $label, true));
    }

    private static function ref(): string
    {
        return self::d('ki/ref');
    }

    private static function map(): string
    {
        return self::d('ki/map');
    }

    /** The goal commitment built WITHOUT the library: literal canonical JSON (sorted keys, NUL escaped as \u0000). */
    private static function commit(string $salt = self::SALT, ?string $ref = null, ?string $map = null): string
    {
        $json = '{"d":"atlas-pca/goal/v1\u0000","goal":"pca-intent:v1:' . ($ref ?? self::ref()) . ':' . ($map ?? self::map())
            . '","salt":"' . $salt . '"}';
        return Pca::b64u(hash('sha256', $json, true));
    }

    /** @return array<string,mixed> */
    private static function env(string $salt = self::SALT): array
    {
        return ['type' => 'envelope', 'goal_commit' => self::commit($salt)];
    }

    /** @return array<string,mixed> */
    private static function ia(array $over = []): array
    {
        return array_merge(['ref' => self::ref(), 'map_digest' => self::map(), 'goal_salt' => self::SALT,
            'fidelity_ppm' => 950000, 'residual_risk_ppm' => 4310000], $over);
    }

    private static function intent(array $over = []): Obj
    {
        return self::o(self::ia($over));
    }

    private static function without(string $k): Obj
    {
        return self::o(array_diff_key(self::ia(), [$k => true]));
    }

    private static function wire(array $over): ?string
    {
        return Pca::validateIntentWire(self::intent($over));
    }

    private static function g(array $caveats): Obj
    {
        return self::o(['caveats' => $caveats]);
    }

    private static function vector(): Obj
    {
        foreach (Corpus::core()->get('vectors') as $v) {
            if ($v->get('name') === 'valid-in-plan-action') {
                return $v;
            }
        }
        throw new \RuntimeException('valid-in-plan-action vector missing');
    }

    /** A signed root grant (issuer = principal, holder = agent) carrying `$caveats`. */
    private static function root(array $caveats): Obj
    {
        $issuer = self::key('principal')[0];
        $holder = self::key('agent')[0];
        $digest = Pca::hashCanonical(self::o(['issuer' => $issuer, 'holder' => $holder, 'caveats' => $caveats, 'parent' => null]));
        return self::o([
            'id' => $digest, 'issuer' => $issuer, 'holder' => $holder, 'body_digest' => $digest, 'caveats' => $caveats,
            'sig' => self::sign('principal', Pca::CAP_DOMAIN . Pca::unb64u($digest, 32)),
        ]);
    }

    private static function grant(): Obj
    {
        return self::root([['type' => 'max_spend', 'usd' => 1], self::env()]);
    }

    /** The corpus valid PCActn re-rooted at `$root`, carrying `$intent` when `$with`, signed by the agent. */
    private static function build(Obj $root, mixed $intent = null, bool $with = true): Obj
    {
        $p = Json::parseLax(Json::canonicalizeStrict(self::vector()->get('pcactn')));
        $p->set('cap_chain', [$root]);
        $p->set('grant_ref', $root->get('id'));
        if ($with) {
            $p->set('intent', $intent);
        }
        $p->set('sig', self::sign('agent', Pca::thresholdMessage($p)));
        return $p;
    }

    private static function verify(Obj $p, Obj $grant, mixed $policy = null, ?string $aud = null): array
    {
        $ctx = self::vector()->get('context');
        return Pca::verifyPcactnCore($p, $grant, $ctx->get('now')->int(), $aud ?? $ctx->get('aud'), null, $policy);
    }

    /** @return array<string,bool> */
    private static function allOk(): array
    {
        return array_fill_keys(self::BASE, true);
    }

    /** @return array<string,bool> */
    private static function withIntent(bool $ok = true): array
    {
        return self::allOk() + ['intent' => $ok];
    }

    private static function decide(mixed $intent, mixed $grant, mixed $policy = null): array
    {
        return Pca::decideIntentBinding($intent, $grant, $policy);
    }

    // ---- constants --------------------------------------------------------------------------------------------------

    public function testConstants(): void
    {
        $this->assertSame('pca-intent:v1:', Pca::INTENT_GOAL_PREFIX);
        $this->assertSame("atlas-pca/goal/v1\0", Pca::INTENT_GOAL_COMMIT_DOMAIN);
        $this->assertSame(1000000, Pca::PPM_ONE);
        $this->assertSame(128, Pca::MAX_INTENT_GOAL_SALT_LEN);
        $this->assertSame(['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm'], Pca::ENVELOPE_INTENT_FIELDS);
    }

    // ---- validateIntentWire -----------------------------------------------------------------------------------------

    public function testWireEdgesAccepted(): void
    {
        $this->assertNull(Pca::validateIntentWire(self::intent()));
        $this->assertNull(self::wire(['fidelity_ppm' => 0]));
        $this->assertNull(self::wire(['fidelity_ppm' => 1000000]));
        $this->assertNull(self::wire(['residual_risk_ppm' => 0]));
        $this->assertNull(self::wire(['residual_risk_ppm' => self::MAX_SAFE]));
        $this->assertNull(self::wire(['goal_salt' => str_repeat("\u{e9}", 64)])); // exactly 128 UTF-8 bytes
        $this->assertNull(self::wire(['goal_salt' => str_repeat('a', 128)]));
        $this->assertNull(self::wire(['goal_salt' => 'a']));
    }

    public function testWireNotAnObject(): void
    {
        foreach ([null, [self::intent()], [], 'x', new Num('1'), true] as $i => $v) {
            $this->assertSame("'intent' must be an object", Pca::validateIntentWire($v), "case $i");
        }
    }

    public function testWireUnknownAndMissing(): void
    {
        $this->assertSame("unknown field 'intent.note'", self::wire(['note' => 'x']));
        $m = self::without('ref');
        $m->set('extra', new Num('1'));
        $this->assertSame("unknown field 'intent.extra'", Pca::validateIntentWire($m)); // unknown before missing
        foreach (['ref', 'map_digest', 'goal_salt', 'fidelity_ppm', 'residual_risk_ppm'] as $k) {
            $this->assertSame("missing field 'intent.$k'", Pca::validateIntentWire(self::without($k)), $k);
        }
        $this->assertSame("missing field 'intent.ref'", Pca::validateIntentWire(new Obj()));
    }

    public function testWireDigests(): void
    {
        $r = "'intent.ref' is not canonical base64url (32 bytes)";
        $m = "'intent.map_digest' is not canonical base64url (32 bytes)";
        $this->assertSame($r, self::wire(['ref' => Pca::b64u(str_repeat('x', 31))]));
        $this->assertSame($r, self::wire(['ref' => Pca::b64u(str_repeat('x', 33))]));
        $this->assertSame($r, self::wire(['ref' => self::ref() . '=']));
        $this->assertSame($r, self::wire(['ref' => 1]));
        $this->assertSame($r, self::wire(['ref' => null]));
        $this->assertSame($m, self::wire(['map_digest' => Pca::b64u(str_repeat('x', 31))]));
        $this->assertSame($m, self::wire(['map_digest' => '+' . substr(self::map(), 1)]));
        $this->assertSame($m, self::wire(['map_digest' => 1]));
        $this->assertSame($r, self::wire(['ref' => 1, 'map_digest' => 1]));
    }

    public function testWireGoalSalt(): void
    {
        $s = "'intent.goal_salt' must be a non-empty string (<= 128 UTF-8 bytes)";
        foreach (['', str_repeat("\u{e9}", 64) . 'a', str_repeat('a', 129), str_repeat("\u{e9}", 65), 5, null, ['a']] as $i => $bad) {
            $this->assertSame($s, self::wire(['goal_salt' => $bad]), "case $i");
        }
    }

    public function testWireFidelityAndResidual(): void
    {
        $f = "'intent.fidelity_ppm' must be a safe integer in [0, 1000000]";
        $r = "'intent.residual_risk_ppm' must be a non-negative safe integer";
        foreach ([-1, 1000001, 1.5, '950000', true, false, null] as $i => $bad) {
            $this->assertSame($f, self::wire(['fidelity_ppm' => $bad]), "fidelity $i");
        }
        foreach (['-0', '1.0', '1e3', '9007199254740992'] as $lex) {
            $i = self::intent();
            $i->set('fidelity_ppm', new Num($lex));
            $this->assertSame($f, Pca::validateIntentWire($i), "fidelity $lex");
        }
        foreach ([-1, 0.25, '1', true, false, null] as $i => $bad) {
            $this->assertSame($r, self::wire(['residual_risk_ppm' => $bad]), "residual $i");
        }
        foreach (['-0', '1.0', '9007199254740992'] as $lex) {
            $i = self::intent();
            $i->set('residual_risk_ppm', new Num($lex));
            $this->assertSame($r, Pca::validateIntentWire($i), "residual $lex");
        }
        $this->assertSame($f, self::wire(['fidelity_ppm' => -1, 'residual_risk_ppm' => -1])); // fidelity first
    }

    public function testWireIsTerminalInVerify(): void
    {
        $g = self::grant();
        $this->assertNull(Pca::validateWire(self::build($g, self::intent())));
        $this->assertNull(Pca::validateWire(self::build($g, null, false)));
        $bad = ['x', null, [self::intent()], self::intent(['note' => 1]), self::without('goal_salt'),
            self::intent(['fidelity_ppm' => true]), self::intent(['residual_risk_ppm' => true]),
            self::intent(['goal_salt' => str_repeat("\u{e9}", 64) . 'a']), self::intent(['fidelity_ppm' => 1000001])];
        foreach ($bad as $i => $intent) {
            $p = self::build($g, $intent);
            $want = Pca::validateIntentWire($intent);
            $this->assertNotNull($want, "case $i");
            $this->assertSame($want, Pca::validateWire($p), "case $i");
            $r = self::verify($p, $g);
            $this->assertSame(['allow' => false, 'checks' => ['wire' => false], 'reason' => 'wire: ' . $want], $r, "case $i");
        }
    }

    // ---- goal helpers -----------------------------------------------------------------------------------------------

    public function testIntentGoalAndCommit(): void
    {
        $ref = self::ref();
        $map = self::map();
        $this->assertSame('pca-intent:v1:' . $ref, Pca::intentGoal($ref));
        $this->assertSame('pca-intent:v1:' . $ref, Pca::intentGoal($ref, null));
        $this->assertSame('pca-intent:v1:' . $ref, Pca::intentGoal($ref, ''));
        $this->assertSame('pca-intent:v1:' . $ref . ':' . $map, Pca::intentGoal($ref, $map));
        $this->assertSame(self::commit(), Pca::intentGoalCommit($ref, $map, self::SALT));
        $this->assertSame(self::commit("\u{e9}"), Pca::intentGoalCommit($ref, $map, "\u{e9}"));
        $this->assertNotSame(self::commit(), Pca::intentGoalCommit($map, $ref, self::SALT));
    }

    public function testIntentPolicyActive(): void
    {
        $inactive = [null, [], ['require' => false], ['require' => 1], ['require' => 'true'], ['require' => null],
            'min_fidelity_ppm', 1, new Obj(), self::o(['require' => false]), self::o(['require' => 1])];
        foreach ($inactive as $i => $p) {
            $this->assertFalse(Pca::intentPolicyActive($p), "inactive $i");
        }
        $active = [['require' => true], ['min_fidelity_ppm' => 0], ['max_residual_risk_ppm' => 0], ['min_fidelity_ppm' => -1],
            ['max_residual_risk_ppm' => null], ['require' => false, 'min_fidelity_ppm' => 1], self::o(['require' => true]),
            self::o(['min_fidelity_ppm' => 0]), self::o(['max_residual_risk_ppm' => 0])];
        foreach ($active as $i => $p) {
            $this->assertTrue(Pca::intentPolicyActive($p), "active $i");
        }
    }

    public function testRootGoalCommit(): void
    {
        $c = self::commit();
        $e = self::env();
        $this->assertSame($c, Pca::rootGoalCommit(self::grant()));
        $this->assertSame($c, Pca::rootGoalCommit(self::g([$e])));
        $this->assertSame('decoy', Pca::rootGoalCommit(self::g([['type' => 'envelope', 'goal_commit' => 'decoy'], $e])));
        // non-object / non-envelope caveats before the envelope are skipped
        $this->assertSame($c, Pca::rootGoalCommit(self::g(['envelope', 1, null, [$e], ['type' => 'Envelope', 'goal_commit' => 'x'], $e])));
        // the first envelope without a string goal_commit ends the search
        $this->assertNull(Pca::rootGoalCommit(self::g([['type' => 'envelope', 'goal_commit' => 7], $e])));
        $this->assertNull(Pca::rootGoalCommit(self::g([['type' => 'envelope'], $e])));
        $this->assertNull(Pca::rootGoalCommit(self::g([])));
        $this->assertNull(Pca::rootGoalCommit(self::o(['caveats' => $e])));
        $this->assertNull(Pca::rootGoalCommit(self::o(['caveats' => null])));
        $this->assertNull(Pca::rootGoalCommit(new Obj()));
        $this->assertNull(Pca::rootGoalCommit(null));
        $this->assertNull(Pca::rootGoalCommit(['caveats' => [self::o($e)]]));
    }

    // ---- decideIntentBinding ----------------------------------------------------------------------------------------

    public function testDecideAbsentAndRequired(): void
    {
        $g = self::g([self::env()]);
        $absent = ['status' => 'absent', 'reason' => ''];
        foreach ([null, [], ['require' => false], ['require' => 1], 'min_fidelity_ppm', self::o(['require' => false])] as $i => $p) {
            $this->assertSame($absent, self::decide(null, $g, $p), "absent $i");
        }
        $this->assertSame($absent, self::decide(null, null));
        foreach ([['require' => true], ['min_fidelity_ppm' => 0], ['max_residual_risk_ppm' => 0], self::o(['require' => true])] as $i => $p) {
            $this->assertSame(['status' => 'fail', 'reason' => self::REQ], self::decide(null, $g, $p), "required $i");
        }
        $this->assertSame(['status' => 'fail', 'reason' => self::MIS], self::decide(null, $g, ['min_fidelity_ppm' => -1]));
        // a present non-object slot never binds
        $this->assertSame(['status' => 'fail', 'reason' => self::REQ], self::decide('x', $g));
    }

    public function testDecideMisconfigured(): void
    {
        $g = self::g([self::env()]);
        $bad = [['min_fidelity_ppm' => -1], ['max_residual_risk_ppm' => -1], ['min_fidelity_ppm' => 0.5],
            ['max_residual_risk_ppm' => 0.5], ['min_fidelity_ppm' => 1.5], ['min_fidelity_ppm' => null], ['min_fidelity_ppm' => true],
            ['max_residual_risk_ppm' => false], ['max_residual_risk_ppm' => '5'], ['min_fidelity_ppm' => self::MAX_SAFE + 1],
            ['max_residual_risk_ppm' => PHP_INT_MAX], ['require' => true, 'min_fidelity_ppm' => 0, 'max_residual_risk_ppm' => -1],
            ['min_fidelity_ppm' => new Num('-1')], ['min_fidelity_ppm' => new Num('0.5')], ['max_residual_risk_ppm' => new Num('-0')],
            ['max_residual_risk_ppm' => new Num('9007199254740992')], self::o(['min_fidelity_ppm' => -1]),
            self::o(['max_residual_risk_ppm' => 0.5])];
        foreach ($bad as $i => $p) {
            $this->assertSame(['status' => 'fail', 'reason' => self::MIS], self::decide(self::intent(), $g, $p), "misconfigured $i");
        }
        $pass = ['status' => 'pass', 'reason' => ''];
        // 0 and MAX_SAFE are valid thresholds (int, Num and Obj forms)
        $this->assertSame($pass, self::decide(self::intent(['fidelity_ppm' => 0]), $g, ['min_fidelity_ppm' => 0, 'max_residual_risk_ppm' => self::MAX_SAFE]));
        $this->assertSame($pass, self::decide(self::intent(['residual_risk_ppm' => 0]), $g, ['max_residual_risk_ppm' => 0]));
        $this->assertSame($pass, self::decide(self::intent(['fidelity_ppm' => 0]), $g, ['min_fidelity_ppm' => new Num('0')]));
        $this->assertSame($pass, self::decide(self::intent(), $g, ['max_residual_risk_ppm' => new Num('9007199254740991')]));
        $this->assertSame($pass, self::decide(self::intent(['residual_risk_ppm' => 0]), $g, self::o(['max_residual_risk_ppm' => 0])));
    }

    public function testThresholdNumericValueRule(): void
    {
        // valid iff the NUMERIC VALUE is a safe integer >= 0, whatever the form (cross-language rule)
        $g = self::g([self::env()]);
        $i = self::intent();
        $pass = ['status' => 'pass', 'reason' => ''];
        $mis = ['status' => 'fail', 'reason' => self::MIS];
        foreach ([['min_fidelity_ppm' => 950000.0], ['min_fidelity_ppm' => 0.0, 'max_residual_risk_ppm' => 4310000.0],
            ['max_residual_risk_ppm' => 9007199254740991.0], ['min_fidelity_ppm' => new Num('950000.0')],
            ['max_residual_risk_ppm' => new Num('4.31e6')], ['min_fidelity_ppm' => new Num('0')],
            Json::parseLax('{"min_fidelity_ppm":950000.0,"max_residual_risk_ppm":4.31e6}'), ['max_residual_risk_ppm' => self::MAX_SAFE]] as $k => $p) {
            $this->assertSame($pass, self::decide($i, $g, $p), "valid $k");
        }
        $this->assertSame($pass, self::decide(self::intent(['fidelity_ppm' => 1000000]), $g, ['min_fidelity_ppm' => 1e6]));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent fidelity 999999 ppm is below the policy minimum 1000000'],
            self::decide(self::intent(['fidelity_ppm' => 999999]), $g, ['min_fidelity_ppm' => 1e6]));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent residual risk 4310000 ppm exceeds the policy maximum 4309999'],
            self::decide($i, $g, ['max_residual_risk_ppm' => 4309999.0]));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent fidelity 950000 ppm is below the policy minimum 950001'],
            self::decide($i, $g, ['min_fidelity_ppm' => new Num('950001.0')]));
        foreach ([['min_fidelity_ppm' => -0.0], ['max_residual_risk_ppm' => -0.0], ['min_fidelity_ppm' => 950000.5],
            ['max_residual_risk_ppm' => 4310000.5], ['min_fidelity_ppm' => -1.0], ['min_fidelity_ppm' => NAN],
            ['max_residual_risk_ppm' => INF], ['min_fidelity_ppm' => -INF], ['max_residual_risk_ppm' => 9007199254740992.0],
            ['min_fidelity_ppm' => self::MAX_SAFE + 1], ['min_fidelity_ppm' => new Num('-0')], ['min_fidelity_ppm' => new Num('-0.0')],
            ['max_residual_risk_ppm' => new Num('1e400')], ['max_residual_risk_ppm' => new Num('950000.5')],
            Json::parseLax('{"min_fidelity_ppm":-0}'), Json::parseLax('{"min_fidelity_ppm":-0.0}')] as $k => $p) {
            $this->assertSame($mis, self::decide($i, $g, $p), "misconfigured $k");
        }
    }

    public function testDecideBinding(): void
    {
        $e = self::env();
        $g = self::g([['type' => 'max_spend', 'usd' => 1], $e]);
        $pass = ['status' => 'pass', 'reason' => ''];
        $noenv = ['status' => 'fail', 'reason' => self::NOENV];
        $open = ['status' => 'fail', 'reason' => self::OPEN];
        $this->assertSame($pass, self::decide(self::intent(), $g));
        $this->assertSame($pass, self::decide(self::intent(), $g, ['require' => true]));
        $this->assertSame($pass, self::decide(self::intent(), $g, 'min_fidelity_ppm'));
        $this->assertSame($noenv, self::decide(self::intent(), self::g([])));
        $this->assertSame($noenv, self::decide(self::intent(), new Obj()));
        $this->assertSame($noenv, self::decide(self::intent(), 'grant'));
        $this->assertSame($noenv, self::decide(self::intent(), self::g([['type' => 'envelope', 'goal_commit' => 7]])));
        $this->assertSame($open, self::decide(self::intent(), self::g([['type' => 'envelope', 'goal_commit' => 'decoy'], $e])));
        $this->assertSame($pass, self::decide(self::intent(), self::g(['x', null, 3, $e])));
        $this->assertSame($open, self::decide(self::intent(['goal_salt' => 'wrong']), $g));
        $this->assertSame($open, self::decide(self::intent(['ref' => self::d('ki/other')]), $g));
        $this->assertSame($open, self::decide(self::intent(['map_digest' => self::d('ki/other')]), $g));
        $this->assertSame($open, self::decide(self::intent(['ref' => self::map(), 'map_digest' => self::ref()]), $g));
    }

    public function testDecideThresholdsInclusive(): void
    {
        $g = self::g([self::env()]);
        $pass = ['status' => 'pass', 'reason' => ''];
        $i = self::intent();
        $this->assertSame($pass, self::decide($i, $g, ['min_fidelity_ppm' => 950000]));
        $this->assertSame($pass, self::decide($i, $g, ['min_fidelity_ppm' => 949999]));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent fidelity 950000 ppm is below the policy minimum 950001'],
            self::decide($i, $g, ['min_fidelity_ppm' => 950001]));
        $this->assertSame($pass, self::decide($i, $g, ['max_residual_risk_ppm' => 4310000]));
        $this->assertSame($pass, self::decide($i, $g, ['max_residual_risk_ppm' => 4310001]));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent residual risk 4310000 ppm exceeds the policy maximum 4309999'],
            self::decide($i, $g, ['max_residual_risk_ppm' => 4309999]));
        // Num / Obj thresholds keep their value
        $this->assertSame($pass, self::decide($i, $g, self::o(['min_fidelity_ppm' => 950000, 'max_residual_risk_ppm' => 4310000])));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent fidelity 950000 ppm is below the policy minimum 950001'],
            self::decide($i, $g, self::o(['min_fidelity_ppm' => 950001])));
        $this->assertSame(['status' => 'fail', 'reason' => 'intent residual risk 4310000 ppm exceeds the policy maximum 4309999'],
            self::decide($i, $g, ['max_residual_risk_ppm' => new Num('4309999')]));
        // min before max; binding before thresholds
        $this->assertStringStartsWith('intent fidelity', self::decide($i, $g, ['min_fidelity_ppm' => 950001, 'max_residual_risk_ppm' => 0])['reason']);
        $this->assertSame(['status' => 'fail', 'reason' => self::OPEN],
            self::decide(self::intent(['goal_salt' => 'wrong']), $g, ['min_fidelity_ppm' => 950001]));
    }

    public function testDecideNeverThrows(): void
    {
        $g = self::g([self::env()]);
        foreach ([self::o(['fidelity_ppm' => 1]), self::intent(['ref' => 1])] as $i => $bad) {
            $d = self::decide($bad, $g);
            $this->assertSame('fail', $d['status'], "case $i");
            $this->assertStringStartsWith(self::ERR, $d['reason'], "case $i");
            $this->assertGreaterThan(strlen(self::ERR), strlen($d['reason']), "case $i: the exception message is appended");
        }
    }

    // ---- verifyPcactnCore / verifyJson: the `intent` check in the verdict -------------------------------------------

    public function testVerifyBoundReportsIntentLast(): void
    {
        $g = self::grant();
        $p = self::build($g, self::intent());
        foreach ([null, ['require' => true], ['min_fidelity_ppm' => 950000, 'max_residual_risk_ppm' => 4310000]] as $i => $pol) {
            $r = self::verify($p, $g, $pol);
            $this->assertSame(['allow' => true, 'checks' => self::withIntent(), 'reason' => ''], $r, "policy $i");
        }
        $ctx = self::vector()->get('context');
        $j = Pca::verifyJson(Json::canonicalizeStrict($p), $g, $ctx->get('now')->int(), $ctx->get('aud'), null, ['min_fidelity_ppm' => 950001]);
        $this->assertSame(['allow' => false, 'checks' => self::withIntent(false),
            'reason' => 'intent: intent fidelity 950000 ppm is below the policy minimum 950001'], $j);
    }

    public function testVerifyAbsentIsPreM2AndActiveFails(): void
    {
        $g = self::grant();
        $p = self::build($g, null, false);
        foreach ([null, [], ['require' => false], ['require' => 1], 'x'] as $i => $pol) {
            $this->assertSame(['allow' => true, 'checks' => self::allOk(), 'reason' => ''], self::verify($p, $g, $pol), "inactive $i");
        }
        $ctx = self::vector()->get('context');
        $this->assertSame(self::allOk(), Pca::verifyPcactnCore($p, $g, $ctx->get('now')->int(), $ctx->get('aud'))['checks']);
        foreach ([['require' => true], ['min_fidelity_ppm' => 1], self::o(['max_residual_risk_ppm' => 5])] as $i => $pol) {
            $this->assertSame(['allow' => false, 'checks' => self::withIntent(false), 'reason' => 'intent: ' . self::REQ],
                self::verify($p, $g, $pol), "active $i");
        }
    }

    public function testVerifyIntentFailures(): void
    {
        $g = self::grant();
        $p = self::build($g, self::intent());
        $this->assertSame(['allow' => false, 'checks' => self::withIntent(false), 'reason' => 'intent: ' . self::MIS],
            self::verify($p, $g, ['max_residual_risk_ppm' => -1]));
        $g3 = self::root([['type' => 'envelope', 'goal_commit' => 'decoy'], self::env()]);
        $this->assertSame(['allow' => false, 'checks' => self::withIntent(false), 'reason' => 'intent: ' . self::OPEN],
            self::verify(self::build($g3, self::intent()), $g3));
        $g4 = self::root([['type' => 'envelope', 'goal_commit' => 7]]);
        $this->assertSame(['allow' => false, 'checks' => self::withIntent(false), 'reason' => 'intent: ' . self::NOENV],
            self::verify(self::build($g4, self::intent()), $g4));
        $g5 = self::root([['type' => 'max_spend', 'usd' => 1], ['type' => 'note', 'n' => 1], self::env()]);
        $this->assertSame(['allow' => true, 'checks' => self::withIntent(), 'reason' => ''], self::verify(self::build($g5, self::intent()), $g5));
    }

    public function testVerifyTamperAndFirstReason(): void
    {
        $g = self::grant();
        $p = self::build($g, self::intent());
        $p->set('intent', self::intent(['fidelity_ppm' => 999999]));
        $r = self::verify($p, $g);
        $this->assertFalse($r['allow']);
        $this->assertSame(array_merge(self::allOk(), ['leaf_signature' => false, 'intent' => true]), $r['checks']);
        $this->assertStringStartsWith('leaf_signature: ', $r['reason']);
        $w = self::verify(self::build($g, self::intent()), $g, ['min_fidelity_ppm' => 950001], 'other-aud');
        $this->assertFalse($w['checks']['audience']);
        $this->assertFalse($w['checks']['intent']);
        $this->assertStringStartsWith('audience: ', $w['reason']);
    }

    public function testVerifySignedEdges(): void
    {
        $g = self::grant();
        foreach ([['fidelity_ppm' => 0], ['fidelity_ppm' => 1000000], ['residual_risk_ppm' => 0], ['residual_risk_ppm' => self::MAX_SAFE]] as $i => $over) {
            $this->assertSame(['allow' => true, 'checks' => self::withIntent(), 'reason' => ''],
                self::verify(self::build($g, self::intent($over)), $g), "edge $i");
        }
        $salt = str_repeat("\u{e9}", 64);
        $g2 = self::root([self::env($salt)]);
        $this->assertSame(['allow' => true, 'checks' => self::withIntent(), 'reason' => ''],
            self::verify(self::build($g2, self::intent(['goal_salt' => $salt])), $g2));
    }
}
