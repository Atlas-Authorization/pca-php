<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/K4.php';

use Atlas\Pca\Json;
use Atlas\Pca\K4;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for K4 (the conformance vectors alone left these): pricing-config boundaries and refusals, decide() on
 * non-object inputs, calibration folding (answer checks, continue vs break, the catch), the PAN heuristic (Luhn, length bounds),
 * the network-token binding and the ERC-7715 granted-permission check (case folding, host objects that only look like Obj).
 */
final class K05KillK4Test extends TestCase
{
    private static function principal(): KeyPair
    {
        return new KeyPair(str_repeat("\x07", 32));
    }

    private static function holder(): KeyPair
    {
        return new KeyPair(str_repeat("\x08", 32));
    }

    private static function o(array $v): mixed
    {
        return Json::parseLax(json_encode($v, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /** `$body` signed by `$kp` the way K4 verifies: Ed25519 over hashCanonical({kind, body}). */
    private static function signed(string $kind, array $body, ?KeyPair $kp = null): Obj
    {
        $o = self::o($body);
        $o->set('sig', Pca::b64u(($kp ?? self::principal())->sign(Pca::hashCanonical(Obj::of(['kind' => $kind, 'body' => $o])))));
        return $o;
    }

    private static function config(array $over = [], array $drop = []): Obj
    {
        $c = $over + ['v' => 1, 'principal' => self::principal()->public, 'currency' => 'USD', 'interruptionCost' => 100,
            'maxInterruptionCost' => 1000, 'hardCeilingLoss' => 1000000, 'epoch' => 1, 'tightenStepPpm' => 100000];
        foreach ($drop as $k) {
            unset($c[$k]);
        }
        return self::signed('pca.escalation_pricing', $c);
    }

    /** A host object that answers keys / has / get like an Obj but is not one. */
    private static function lookalike(array $d): object
    {
        return new class ($d) {
            public function __construct(private readonly array $d)
            {
            }

            public function keys(): array
            {
                return array_map('strval', array_keys($this->d));
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->d);
            }

            public function get(string $k): mixed
            {
                return $this->d[$k] ?? null;
            }
        };
    }

    public function testPricingConfigBoundariesAndRefusals(): void
    {
        $this->assertNull(K4::pricingConfigError(self::config()), 'control');
        $this->assertNull(K4::pricingConfigError(self::config(['interruptionCost' => 1000])), 'a cost equal to the max is allowed');
        $this->assertNull(K4::pricingConfigError(self::config(['tightenStepPpm' => 0])), 'a zero step is allowed');
        $this->assertNull(K4::pricingConfigError(self::config(['tightenStepPpm' => K4::MAX_MULTIPLIER_PPM])));
        $this->assertSame('config_step_invalid', K4::pricingConfigError(self::config(['tightenStepPpm' => K4::MAX_MULTIPLIER_PPM + 1])));
        $this->assertSame('config_step_invalid', K4::pricingConfigError(self::config([], ['tightenStepPpm'])));
        $this->assertSame('config_step_invalid', K4::pricingConfigError(self::config(['tightenStepPpm' => -1])));
        $this->assertSame('config_amounts_invalid', K4::pricingConfigError(self::config(['interruptionCost' => -1])));
        $this->assertSame('config_cost_above_max', K4::pricingConfigError(self::config(['interruptionCost' => 1001])));
        // a key or signature that does not decode is malformed, not a bad signature
        $badSig = self::config();
        $badSig->set('sig', '!!');
        $this->assertSame('config_malformed', K4::pricingConfigError($badSig));
        $badKey = self::config(['principal' => '!!']);
        $this->assertSame('config_malformed', K4::pricingConfigError($badKey));
        $other = self::config();
        $other->set('epoch', self::o(['x' => 2])->get('x'));
        $this->assertSame('config_signature_invalid', K4::pricingConfigError($other));
        // a host object is not a config, even when every member reads well
        $this->assertSame('config_malformed', K4::pricingConfigError(self::lookalike(['v' => self::o(['x' => 1])->get('x'),
            'principal' => self::principal()->public, 'currency' => 'USD', 'sig' => 'AA'])));
    }

    private static function risk(array $over = [], array $drop = []): Obj
    {
        $r = $over + ['currency' => 'USD', 'loss' => 10, 'pBadUpperPpm' => 1000];
        foreach ($drop as $k) {
            unset($r[$k]);
        }
        return self::o($r);
    }

    private static function cal(int $m = 1000000): Obj
    {
        return self::o(['multiplierPpm' => $m]);
    }

    public function testDecideOnNonObjectInputs(): void
    {
        $this->assertSame(['ask' => false, 'reason' => 'expected_loss_within_interruption_cost'], K4::decide(self::config(), self::cal(), self::risk()));
        $this->assertSame(['ask' => true, 'reason' => 'calibration_invalid'], K4::decide(self::config(), null, self::risk()));
        $this->assertSame(['ask' => true, 'reason' => 'currency_mismatch'],
            K4::decide(self::config(), self::cal(), self::lookalike(['currency' => 'USD', 'pBadUpperPpm' => 5])));
        $this->assertSame(['ask' => true, 'reason' => 'risk_input_invalid'], K4::decide(self::config(), self::cal(), self::risk([], ['loss'])));
        $this->assertSame(['ask' => true, 'reason' => 'risk_input_invalid'], K4::decide(self::config(), self::cal(), self::risk([], ['pBadUpperPpm'])));
    }

    private const DIGEST = 'ad';

    private static function answer(string $nonce, string $answer = 'deny', array $over = []): Obj
    {
        return self::signed('pca.escalation_answer', $over + ['v' => 1, 'principal' => self::principal()->public, 'nonce' => $nonce,
            'action_digest' => self::DIGEST, 'answer' => $answer]);
    }

    /** @return array{mult: int, seen: list<string>} */
    private static function fold(array $answers, array $seen = []): array
    {
        return K4::updateCalibration(self::config(), 1000000, $seen, $answers, [self::DIGEST => self::risk()]);
    }

    public function testCalibrationFoldsOnlyValidDenials(): void
    {
        $up = 1100000;
        $this->assertSame(['mult' => $up, 'seen' => ['nonce-001']], self::fold([self::answer('nonce-001')]), 'control');
        // an invalid config leaves the calibration exactly as given
        $this->assertSame(['mult' => 5, 'seen' => ['n']], K4::updateCalibration(self::o(['v' => 1]), 5, ['n'], [self::answer('nonce-001')], []));
        // a nonce of exactly 8 UTF-16 units is long enough
        $this->assertSame($up, self::fold([self::answer('12345678')])['mult']);
        $this->assertSame(1000000, self::fold([self::answer('1234567')])['mult']);
        // the answer must be version 1 and name the config's principal (both signed by the principal's key)
        $this->assertSame(1000000, self::fold([self::answer('nonce-001', 'deny', ['v' => 2])])['mult']);
        $this->assertSame(1000000, self::fold([self::answer('nonce-001', 'deny', ['principal' => self::holder()->public])])['mult']);
        // a skipped answer (invalid, or an approval) does not stop the fold: the next denial still counts
        $this->assertSame($up, self::fold([self::answer('nonce-001', 'deny', ['v' => 2]), self::answer('nonce-002')])['mult']);
        $this->assertSame(['mult' => $up, 'seen' => ['nonce-001', 'nonce-002']],
            self::fold([self::answer('nonce-001', 'approve'), self::answer('nonce-002')]));
        // an answer that cannot be canonicalized is not counted (the catch answers false)
        $odd = self::answer('nonce-001');
        $odd->set('x', new \stdClass());
        $this->assertSame(['mult' => 1000000, 'seen' => []], self::fold([$odd]));
    }

    public function testPanHeuristicAndTokenRef(): void
    {
        // Luhn with doubled digits above 4 (5 -> 10 -> 1)
        $this->assertTrue(K4::looksLikePan('5555555555554444'));
        $this->assertTrue(K4::looksLikePan('5555-5555 5555-4444'));
        $this->assertFalse(K4::looksLikePan('5555555555554445'));
        // only runs of 13..19 digits count
        $this->assertFalse(K4::looksLikePan('400000000002'));
        $this->assertTrue(K4::looksLikePan('4000000000006'));
        $this->assertTrue(K4::looksLikePan('4000000000000000006'));
        $this->assertFalse(K4::looksLikePan('40000000000000000002'));
        $this->assertSame('token_ref_looks_like_pan', K4::tokenRefError('tok_5555555555554444'));
        $this->assertNull(K4::tokenRefError('tok_abcdefgh'));
        $this->assertSame('token_ref_malformed', K4::tokenRefError('tok_abc'));
        $this->assertSame('token_ref_malformed', K4::tokenRefError(12345678));
    }

    private static function binding(array $over = [], array $drop = []): Obj
    {
        $grant = self::o(['g' => 1]);
        $b = $over + ['kind' => K4::BINDING_KIND, 'token_ref' => 'tok_abcdefgh', 'provider' => 'visa', 'grant_digest' => Pca::hashCanonical($grant),
            'holder' => self::holder()->public, 'issuer_nonce' => 'nonce-1'];
        foreach ($drop as $k) {
            unset($b[$k]);
        }
        $body = self::o(['kind' => K4::BINDING_KIND, 'v' => 1, 'provider' => $b['provider'] ?? null, 'token_ref' => $b['token_ref'],
            'grant_digest' => $b['grant_digest'], 'issuer_nonce' => $b['issuer_nonce'], 'holder' => $b['holder']]);
        $b['binding_proof'] ??= Pca::b64u(self::holder()->sign(Pca::hashCanonical($body)));
        return self::o($b);
    }

    public function testBindingRefusals(): void
    {
        $grant = self::o(['g' => 1]);
        $h = self::holder()->public;
        $this->assertNull(K4::verifyBinding(self::binding(), $grant, $h, 'nonce-1', 'visa'), 'control');
        $this->assertNull(K4::verifyBinding(self::binding(), $grant, $h, 'nonce-1'), 'any provider when none is required');
        $this->assertSame('binding_malformed', K4::verifyBinding(self::lookalike(['kind' => K4::BINDING_KIND, 'token_ref' => 'x']), $grant, $h, 'nonce-1'));
        $this->assertSame('provider_mismatch', K4::verifyBinding(self::binding([], ['provider']), $grant, $h, 'nonce-1'));
        $this->assertSame('provider_mismatch', K4::verifyBinding(self::binding(['provider' => '']), $grant, $h, 'nonce-1'));
        // a holder key that does not decode is malformed even with a well-formed proof
        $bad = self::binding(['holder' => '!!!!!!!!', 'binding_proof' => Pca::b64u(str_repeat("\x01", 64))]);
        $this->assertSame('binding_malformed', K4::verifyBinding($bad, $grant, '!!!!!!!!', 'nonce-1'));
        $this->assertSame('binding_proof_invalid', K4::verifyBinding(self::binding(['binding_proof' => Pca::b64u(str_repeat("\x01", 64))]),
            $grant, $h, 'nonce-1'));
    }

    private const MGR = '0xabababababababababababababababababababab';

    /** The k4-vectors case "as requested (erc20)", with overrides merged into sent / got. */
    private static function granted(array $sent = [], array $got = [], ?array $allowed = null, array $g = ['grantDigest' => 'gd1', 'expiresAtSec' => 1800086400]): ?string
    {
        $perm = ['type' => 'erc20-token-allowance', 'isAdjustmentAllowed' => true,
            'data' => ['tokenAddress' => '0x2222222222222222222222222222222222222222', 'allowance' => '0x989680']];
        $s = array_replace_recursive(['chainId' => '0x2105', 'to' => '0x1111111111111111111111111111111111111111', 'permission' => $perm,
            'rules' => [['type' => 'expiry', 'data' => ['timestamp' => 1800086400]]]], $sent);
        $r = array_replace_recursive(['chainId' => '0x2105', 'to' => '0x1111111111111111111111111111111111111111', 'permission' => $perm,
            'rules' => [['type' => 'expiry', 'data' => ['timestamp' => 1800086400]]], 'context' => '0xabc123', 'dependencies' => [],
            'delegationManager' => self::MGR], $got);
        foreach ([&$s, &$r] as &$x) {
            foreach ($x as $k => $v) {
                if ($v === null) {
                    unset($x[$k]);
                }
            }
        }
        unset($x);
        return K4::verifyGranted(self::o($g), self::o($s), self::o($r), $allowed ?? [self::MGR],
            static fn (string $c): ?string => $c === '0xabc123' ? 'gd1' : null);
    }

    public function testGrantedPermissionCaseFoldingAndRefusals(): void
    {
        $this->assertNull(self::granted(), 'control');
        $this->assertNull(self::granted(['chainId' => '0xA'], ['chainId' => '0xa']), 'chain ids compare case-insensitively');
        $this->assertNull(self::granted([], [], [strtoupper(self::MGR)]), 'allowed managers compare case-insensitively');
        $this->assertSame('delegation_manager_not_allowed', self::granted([], ['delegationManager' => null]));
        $this->assertSame('delegation_manager_not_allowed', self::granted([], ['delegationManager' => 'mgr'], ['mgr']));
        // from: absent in the request = any; present = must match, case-insensitively
        $this->assertNull(self::granted([], ['from' => '0x3333333333333333333333333333333333333333']));
        $this->assertNull(self::granted(['from' => '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'], ['from' => '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']));
        $this->assertSame('from_mismatch', self::granted(['from' => '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
            ['from' => '0x3333333333333333333333333333333333333333']));
        $this->assertNull(self::granted(['permission' => ['data' => ['tokenAddress' => '0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD']]],
            ['permission' => ['data' => ['tokenAddress' => '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd']]]), 'token addresses compare case-insensitively');
        // the sent allowance is read after its 2-character prefix, whatever that prefix is
        $this->assertSame('amount_widened', self::granted(['permission' => ['data' => ['allowance' => '1234']]],
            ['permission' => ['data' => ['allowance' => '0x100']]]));
        $this->assertSame('response_malformed', self::granted(['permission' => ['data' => ['allowance' => 5]]]));
        // array_replace_recursive keeps the default timestamp, so the data member is replaced whole (no timestamp in it)
        $this->assertSame('expiry_malformed', self::granted([], ['rules' => [['type' => 'expiry', 'data' => 'x']]]));
        // an expiry before the epoch is not past a grant whose expiry is unknown (read as 0)
        $this->assertNull(self::granted([], ['rules' => [['type' => 'expiry', 'data' => ['timestamp' => -5]]]], null, ['grantDigest' => 'gd1']));
        $this->assertSame('expiry_extended', self::granted([], ['rules' => [['type' => 'expiry', 'data' => ['timestamp' => 5]]]], null, ['grantDigest' => 'gd1']));
    }

    public function testGrantedHostObjectsAreNotJsonObjects(): void
    {
        $g = self::o(['grantDigest' => 'gd1', 'expiresAtSec' => 1800086400]);
        $sent = self::o(['chainId' => '0x2105']);
        $got = self::lookalike(['permission' => self::o(['type' => 'x']), 'context' => 'zz']);
        $this->assertSame('response_malformed', K4::verifyGranted($g, $sent, $got, [self::MGR]));
        // a rule that only looks like an object is an unknown rule
        $rule = self::lookalike(['type' => 'expiry', 'data' => self::o(['timestamp' => 1])]);
        $perm = ['type' => 'native-token-allowance', 'isAdjustmentAllowed' => true, 'data' => ['allowance' => '0x3e8']];
        $s = self::o(['chainId' => '0x1', 'to' => '0x1111111111111111111111111111111111111111', 'permission' => $perm]);
        $r = self::o(['chainId' => '0x1', 'to' => '0x1111111111111111111111111111111111111111', 'permission' => $perm, 'context' => '0xabc123',
            'delegationManager' => self::MGR]);
        $r->set('rules', [$rule]);
        $this->assertSame('unknown_rule_type', K4::verifyGranted($g, $s, $r, [self::MGR]));
    }
}
