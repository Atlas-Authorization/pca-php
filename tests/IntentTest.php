<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Intent Layer M2 (`envelope.intent`). The shared `intent-*` conformance vectors (CorpusTest / conformance.php) pin the
 * full contract; these are small native checks: wire refusals, the absent-policy back-compat verdict, policy
 * misconfiguration, and a positive binding on a PCActn re-rooted and re-signed here, whose root grant's goal commitment
 * comes from this library's own canonical hash.
 */
final class IntentTest extends TestCase
{
    private const SALT = 'c2FsdC1pbnRlbnQ';

    private static function o(array $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION));
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

    private static function ref(): string
    {
        return Pca::b64u(hash('sha256', 'intent/ref', true));
    }

    private static function map(): string
    {
        return Pca::b64u(hash('sha256', 'intent/map', true));
    }

    private static function commit(string $salt = self::SALT): string
    {
        return Pca::hashCanonical(Obj::of([
            'd' => "atlas-pca/goal/v1\0",
            'goal' => 'pca-intent:v1:' . self::ref() . ':' . self::map(),
            'salt' => $salt,
        ]));
    }

    /** @return array<string,mixed> */
    private static function intentArr(array $over = []): array
    {
        return array_merge(['ref' => self::ref(), 'map_digest' => self::map(), 'goal_salt' => self::SALT,
            'fidelity_ppm' => 950000, 'residual_risk_ppm' => 4310000], $over);
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

    /** @return list<string> */
    private static function order(): array
    {
        return array_values(array_map(fn($x) => $x, Corpus::core()->get('check_order')));
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
        return self::root([['type' => 'max_spend', 'usd' => 1], ['type' => 'envelope', 'goal_commit' => self::commit()]]);
    }

    /** The corpus valid PCActn re-rooted at `$root`, carrying `$intent` when given, signed by the agent. */
    private static function build(Obj $root, mixed $intent = null, bool $withIntent = true): Obj
    {
        $p = Json::parseLax(Json::canonicalizeStrict(self::vector()->get('pcactn')));
        $p->set('cap_chain', [$root]);
        $p->set('grant_ref', $root->get('id'));
        if ($withIntent && $intent !== null) {
            $p->set('intent', $intent);
        }
        $p->set('sig', self::sign('agent', Pca::thresholdMessage($p)));
        return $p;
    }

    private static function verify(Obj $p, mixed $policy = null, ?Obj $grant = null): array
    {
        $ctx = self::vector()->get('context');
        return Pca::verifyPcactnCore($p, $grant ?? self::grant(), $ctx->get('now')->int(), $ctx->get('aud'), null, $policy);
    }

    public function testPositiveBinding(): void
    {
        $this->assertSame('pca-intent:v1:' . self::ref() . ':' . self::map(), Pca::intentGoal(self::ref(), self::map()));
        $this->assertSame(self::commit(), Pca::intentGoalCommit(self::ref(), self::map(), self::SALT));
        $g = self::grant();
        $p = self::build($g, self::o(self::intentArr()));
        $policies = [null, ['require' => true], self::o(['require' => true]),
            ['min_fidelity_ppm' => 950000, 'max_residual_risk_ppm' => 4310000]];
        foreach ($policies as $i => $pol) {
            $r = self::verify($p, $pol, $g);
            $this->assertTrue($r['allow'], "policy $i: {$r['reason']}");
            $this->assertTrue($r['checks']['intent'], "policy $i");
            $this->assertSame([...self::order(), 'intent'], array_keys($r['checks']), "policy $i");
        }
        $r = self::verify($p, ['min_fidelity_ppm' => 950001], $g);
        $this->assertFalse($r['allow']);
        $this->assertFalse($r['checks']['intent']);
        $this->assertStringStartsWith('intent:', $r['reason']);
        $r = self::verify($p, ['max_residual_risk_ppm' => 4309999], $g);
        $this->assertFalse($r['checks']['intent']);
    }

    public function testBindingMismatches(): void
    {
        $cases = [
            'no envelope' => self::root([['type' => 'max_spend', 'usd' => 1]]),
            'first envelope wins' => self::root([['type' => 'envelope', 'goal_commit' => 'x'], ['type' => 'envelope', 'goal_commit' => self::commit()]]),
            'goal_commit not a string' => self::root([['type' => 'envelope', 'goal_commit' => 7]]),
        ];
        foreach ($cases as $label => $g) {
            $r = self::verify(self::build($g, self::o(self::intentArr())), null, $g);
            $this->assertFalse($r['allow'], $label);
            $this->assertTrue($r['checks']['leaf_signature'], $label);
            $this->assertFalse($r['checks']['intent'], $label);
        }
        $g = self::grant();
        $r = self::verify(self::build($g, self::o(self::intentArr(['goal_salt' => 'wrong']))), null, $g);
        $this->assertFalse($r['checks']['intent']);
    }

    public function testUnsignedTamperBreaksLeafSignature(): void
    {
        $g = self::grant();
        $p = self::build($g, self::o(self::intentArr()));
        $p->set('intent', self::o(self::intentArr(['fidelity_ppm' => 999999])));
        $r = self::verify($p, null, $g);
        $this->assertFalse($r['allow']);
        $this->assertFalse($r['checks']['leaf_signature']);
        $this->assertTrue($r['checks']['intent']);
    }

    public function testAbsentIntentBackCompatAndActivePolicy(): void
    {
        $g = self::grant();
        $p = self::build($g, null, false);
        foreach ([null, [], ['require' => false], ['require' => 1], self::o(['require' => false]), 'not-a-policy'] as $i => $pol) {
            $r = self::verify($p, $pol, $g);
            $this->assertTrue($r['allow'], "inactive $i: {$r['reason']}");
            $this->assertSame(self::order(), array_keys($r['checks']), "inactive $i");
        }
        foreach ([['require' => true], ['min_fidelity_ppm' => 1], self::o(['max_residual_risk_ppm' => 5])] as $i => $pol) {
            $r = self::verify($p, $pol, $g);
            $this->assertFalse($r['allow'], "active $i");
            $this->assertFalse($r['checks']['intent'], "active $i");
            $this->assertSame([...self::order(), 'intent'], array_keys($r['checks']), "active $i");
        }
    }

    public function testPolicyMisconfiguredFailsClosed(): void
    {
        $g = self::grant();
        $intent = self::o(self::intentArr());
        $bad = [['min_fidelity_ppm' => -1], ['max_residual_risk_ppm' => 0.5], ['min_fidelity_ppm' => null],
            ['min_fidelity_ppm' => true], ['max_residual_risk_ppm' => '5'], self::o(['min_fidelity_ppm' => -1]),
            self::o(['max_residual_risk_ppm' => 0.5])];
        foreach ($bad as $i => $pol) {
            $d = Pca::decideIntentBinding($intent, $g, $pol);
            $this->assertSame('fail', $d['status'], "misconfigured $i");
            $this->assertStringContainsString('misconfigured', $d['reason'], "misconfigured $i");
        }
    }

    public function testWireRefusalsAreTerminal(): void
    {
        $g = self::grant();
        $base = self::intentArr();
        $without = fn(string $k) => array_diff_key($base, [$k => true]);
        $bad = [
            'x', [self::o($base)], self::o(self::intentArr(['note' => 'x'])), self::o($without('goal_salt')),
            self::o($without('residual_risk_ppm')), self::o(self::intentArr(['ref' => self::ref() . '='])),
            self::o(self::intentArr(['map_digest' => '+' . substr(self::map(), 1)])), self::o(self::intentArr(['ref' => 1])),
            self::o(self::intentArr(['ref' => Pca::b64u(str_repeat('x', 31))])), self::o(self::intentArr(['goal_salt' => ''])),
            self::o(self::intentArr(['goal_salt' => str_repeat("\u{e9}", 64) . 'a'])), self::o(self::intentArr(['goal_salt' => 5])),
            self::o(self::intentArr(['fidelity_ppm' => 1000001])), self::o(self::intentArr(['fidelity_ppm' => -1])),
            self::o(self::intentArr(['fidelity_ppm' => 1.5])), self::o(self::intentArr(['fidelity_ppm' => '950000'])),
            self::o(self::intentArr(['residual_risk_ppm' => -1])), self::o(self::intentArr(['residual_risk_ppm' => 0.25])),
            self::o(self::intentArr(['residual_risk_ppm' => true])),
        ];
        foreach ($bad as $i => $intent) {
            $r = self::verify(self::build($g, $intent), null, $g);
            $this->assertFalse($r['allow'], "wire $i");
            $this->assertSame(['wire' => false], $r['checks'], "wire $i: {$r['reason']}");
        }
        // null intent: the slot is present but not an object
        $p = self::build($g, null, false);
        $p->set('intent', null);
        $this->assertSame(['wire' => false], self::verify($p, null, $g)['checks']);
    }

    public function testWellFormedEdges(): void
    {
        $salt = str_repeat("\u{e9}", 64); // 128 UTF-8 bytes
        $g = self::root([['type' => 'envelope', 'goal_commit' => self::commit($salt)]]);
        $r = self::verify(self::build($g, self::o(self::intentArr(['goal_salt' => $salt]))), null, $g);
        $this->assertTrue($r['allow'], $r['reason']);
        $g = self::grant();
        foreach ([['fidelity_ppm' => 1000000, 'residual_risk_ppm' => 0], ['residual_risk_ppm' => 9007199254740991]] as $i => $over) {
            $r = self::verify(self::build($g, self::o(self::intentArr($over))), null, $g);
            $this->assertTrue($r['allow'], "edge $i: {$r['reason']}");
        }
    }
}
