<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AssuranceRequirement;
use Atlas\Pca\Beacons;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\VerifyVerdict;
use PHPUnit\Framework\TestCase;

/**
 * The resource-server verdict over one real signed PCActn and its variations: each scenario changes one input (the clock, the
 * shape of an option, a hook's answer, a pin, the plan, the budget, a delegated caveat ...) and its whole verdict is pinned:
 * allow, r, the required threshold, the reasons in order, every check that differs from the allowed baseline, the budget
 * and a digest of the assurance report. The pinned verdicts are this verifier's (they agree with the TS reference wherever the
 * shared corpus covers the input).
 */
final class ProofSurvivorKill5VerifyVerdictTest extends TestCase
{
    public const NOW = 1791288000000;

    /** The checks of the allowed baseline; a scenario lists only how its checks differ (null: the check is absent). */
    private const BASE_CHECKS = ['wire' => 'pass', 'version' => 'pass', 'audience' => 'pass', 'validity' => 'pass', 'cap_chain' => 'pass',
        'grant_ref_bound' => 'pass', 'plan_inclusion' => 'pass', 'leaf_signature' => 'pass', 'counter_format' => 'pass', 'plan_root_authorized' => 'pass',
        'taint_gate' => 'not-enforced', 'attestation' => 'not-enforced', 'threshold' => 'not-enforced', 'revocation' => 'pass', 'grant_ref' => 'pass',
        'params_digest' => 'not-enforced', 'freshness' => 'not-enforced', 'beacon' => 'not-enforced', 'budget' => 'pass', 'delegated_caveats' => 'pass', 'policy' => 'pass'];

    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function plan(string $class = 'reversible'): array
    {
        return [['id' => 'n1', 'verb' => 'v', 'resource' => 'r', 'reversibility_class' => $class], ['id' => 'n2', 'verb' => 'w', 'resource' => 'r']];
    }

    private static function grant(array $env = []): Obj
    {
        return Sign::mintGrant(self::kp(1), self::kp(2)->public, $env + ['predicates' => [['verb' => 'v', 'resource' => 'r'], ['verb' => 'w', 'resource' => 'r']],
            'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()], 'g', 's')['grant'];
    }

    /** A PCActn for plan node n1 signed by the grant holder (chain: the grant alone unless given). */
    private static function pcactn(?Obj $g = null, array $extra = [], ?array $chain = null, int $iat = self::NOW, int $ttl = 60000, string $class = 'reversible', int $signer = 2): Obj
    {
        $g ??= self::grant();
        return Sign::buildPcactn($g, $chain ?? [$g], self::plan($class), 'n1', 1, self::kp($signer), 'aud', null, $iat, $iat + $ttl, $ttl, $extra);
    }

    /** A PCActn signed by agent 3 under the grant delegated from agent 2 with the extra caveats. @return array{0: Obj, 1: array} */
    private static function delegated(array $caveats, array $ctx = [], array $o = []): array
    {
        $g = self::grant();
        $child = Sign::delegate($g, self::kp(2), self::kp(3)->public, $caveats);
        return [self::pcactn($g, chain: [$g, $child], signer: 3), self::opts($g, $ctx, $o)];
    }

    private static function riskLow(): array
    {
        return ['reversibility' => 1, 'blastRadius' => 0, 'confidence' => 1, 'semanticDistance' => 0, 'taint' => 0];
    }

    private static function riskHigh(): array
    {
        return ['reversibility' => 0, 'blastRadius' => 1, 'confidence' => 0, 'semanticDistance' => 1, 'taint' => 1];
    }

    private static function revOk(): \Closure
    {
        return static fn(): array => ['enforced' => true, 'ok' => true];
    }

    /** Verifier options of the allowed baseline; `$ctx` overrides context members, `$o` top-level options. */
    private static function opts(?Obj $g = null, array $ctx = [], array $o = []): array
    {
        return $o + ['grant' => $g ?? self::grant(), 'now' => self::NOW, 'audience' => 'aud', 'hooks' => ['revocation' => self::revOk()],
            'context' => Sign::n($ctx + ['plan' => self::plan(), 'planAuthorized' => true, 'risk' => self::riskLow(), 'budget' => ['B' => 1, 'tau' => self::NOW, 'asOf' => self::NOW]])];
    }

    /** A copy of `$o` with members replaced (a null value removes the member). */
    private static function with(Obj $o, array $set): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            if (!array_key_exists($k, $set)) {
                $c->set($k, $o->get($k));
            }
        }
        foreach ($set as $k => $v) {
            if ($v !== null) {
                $c->set((string) $k, $v);
            }
        }
        return $c;
    }

    /** @return array<string,mixed> the verdict reduced to what is pinned */
    public static function summary(array $v): array
    {
        $diff = [];
        $closed = count($v['checks']) < 5;
        if ($closed) {
            $diff = $v['checks']; // a fail-closed verdict: its few checks in full
        } else foreach ($v['checks'] as $k => $s) {
            if ((self::BASE_CHECKS[$k] ?? null) !== $s) {
                $diff[(string) $k] = $s;
            }
        }
        foreach (self::BASE_CHECKS as $k => $s) {
            if (!$closed && !array_key_exists($k, $v['checks'])) {
                $diff[$k] = null;
            }
        }
        $rt = $v['requiredThreshold'];
        // a PHP TypeError names the calling file and line: not part of the verdict's meaning
        $reasons = array_map(static fn(string $r): string => (string) preg_replace('/, called in .* on line \d+/', '', $r), $v['reasons']);
        $out = ['allow' => $v['allow'], 'r' => $v['r'], 'threshold' => $rt['t'] . '/' . $rt['proof'] . '/' . ($rt['optimisticAllowed'] ? 'optimistic' : 'strict'),
            'reasons' => $reasons, 'checks' => $diff];
        if (array_key_exists('budget', $v)) {
            $out['budget'] = json_encode($v['budget']);
        }
        if (array_key_exists('assurance', $v)) {
            $out['assurance'] = sha1((string) json_encode($v['assurance']));
        }
        return $out;
    }

    /** @return array<string, \Closure(): array{0: mixed, 1: mixed, 2?: \Closure(): mixed}> [pcactn, options, extra observation] */
    public static function scenarios(): array
    {
        $s = [];
        $s['base'] = static fn() => [self::pcactn(), self::opts()];
        // ---- the grant and the clock
        $s['grant null'] = static fn() => [self::pcactn(), self::opts(o: ['grant' => null])];
        $s['grant without caveats'] = static fn() => [self::pcactn(), self::opts(o: ['grant' => self::with(self::grant(), ['caveats' => null])])];
        $s['grant as an array'] = static fn() => [self::pcactn(), self::opts(o: ['grant' => ['caveats' => []]])];
        $s['clock NaN, requireAssurance null'] = static fn() => [self::pcactn(), self::opts(o: ['now' => NAN, 'requireAssurance' => null])];
        $s['clock NaN, requireAssurance set'] = static fn() => [self::pcactn(), self::opts(o: ['now' => NAN, 'requireAssurance' => Obj::of(['signature' => 'classical'])])];
        $s['clock NaN, assurance'] = static fn() => [self::pcactn(), self::opts(o: ['now' => NAN, 'assurance' => true])];
        $s['clock 2^53 - 1'] = static fn() => [self::pcactn(), self::opts(o: ['now' => 9007199254740991])];
        $s['clock 2^53'] = static fn() => [self::pcactn(), self::opts(o: ['now' => 9007199254740992.0])];
        $s['clock with a fraction'] = static fn() => [self::pcactn(), self::opts(o: ['now' => self::NOW + 0.5])];
        $s['clock with a fraction, bad signature'] = static fn() => [self::with(self::pcactn(), ['counter' => Sign::n(2)]), self::opts(o: ['now' => self::NOW + 0.5])];
        $s['clock as an integral float'] = static fn() => [self::pcactn(), self::opts(o: ['now' => (float) self::NOW])];
        $seen = new \ArrayObject();
        $s['hook context under an unsafe clock'] = static function () use ($seen) {
            $o = self::opts(o: ['now' => self::NOW + 0.5]);
            $o['hooks'] = ['revocation' => static function (array $c) use ($seen): array {
                $seen['keys'] = array_keys($c);
                $seen['nowEpoch'] = $c['nowEpoch'];
                $seen['pcactn'] = $c['pcactn'] instanceof Obj;
                return ['enforced' => true, 'ok' => true];
            }];
            return [self::pcactn(), $o, static fn() => $seen->getArrayCopy()];
        };
        $s['the wall clock'] = static function () {
            $now = (int) (microtime(true) * 1000);
            $o = self::opts();
            unset($o['now']);
            $o['context'] = self::with($o['context'], ['budget' => null]);
            return [self::pcactn(iat: $now - 1000), $o];
        };
        // ---- option shapes
        $s['context as an associative array'] = static function () {
            $c = self::opts()['context'];
            $a = [];
            foreach ($c->keys() as $k) {
                $a[$k] = $c->get($k);
            }
            $a[7] = 'x';
            return [self::pcactn(), self::opts(o: ['context' => $a])];
        };
        $s['operation as an array'] = static fn() => [self::pcactn(), self::opts(o: ['operation' => ['verb' => 'v', 'resource' => 'r']])];
        $s['operation for another verb'] = static fn() => [self::pcactn(), self::opts(o: ['operation' => ['verb' => 'w', 'resource' => 'r']])];
        $s['operation as an empty array'] = static fn() => [self::pcactn(), self::opts(o: ['operation' => []])];
        $s['hooks as an object'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => Obj::of(['revocation' => self::revOk()])])];
        $s['attestation gate as an object'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => Obj::of(['attestation' => Obj::of(['x' => 1])])])];
        $s['attestation gate as an array'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['attestation' => ['x' => 1]]])];
        $s['attestation gate not required'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['attestation' => ['required' => false]]])];
        // ---- reason texts
        $s['lifetime too long'] = static fn() => [self::pcactn(ttl: 86400000 * 400), self::opts()];
        $s['version with a newline'] = static fn() => [self::with(self::pcactn(), ['ver' => "x\ny"]), self::opts()];
        // ---- hooks
        $s['attestation and zk hooks both throw'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(),
            'attestation' => static fn() => throw new \RuntimeException('first'), 'zk' => static fn() => throw new \RuntimeException('second')]])];
        $s['attestation and zk hooks both answer null'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(),
            'attestation' => static fn() => null, 'zk' => static fn() => null]])];
        $s['attestation hook answers a string'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(), 'attestation' => static fn() => 'x']])];
        $s['revocation hook answers nothing'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => static fn() => []]])];
        $s['revocation hook enforces without ok'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => static fn() => ['enforced' => true]]])];
        $s['revocation hook answers a string'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => static fn() => 'x']])];
        $s['revocation hook throws'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => static fn() => throw new \RuntimeException('rev')]])];
        $s['threshold hook throws'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(), 'threshold' => static fn() => throw new \RuntimeException('thr')]])];
        $s['attestation throws after a threshold refusal'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(),
            'threshold' => static fn() => ['enforced' => true, 'ok' => false, 'reason' => 'no'], 'attestation' => static fn() => throw new \RuntimeException('att')]])];
        $s['revocation throws after a threshold refusal'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => [
            'threshold' => static fn() => ['enforced' => true, 'ok' => false, 'reason' => 'no'], 'revocation' => static fn() => throw new \RuntimeException('rev')]])];
        $s['zk refusal then revocation throws'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => [
            'zk' => static fn() => ['enforced' => true, 'ok' => false, 'reason' => 'zk_compliance proof missing'], 'revocation' => static fn() => throw new \RuntimeException('rev')]])];
        // ---- the threshold hook against a high-risk action (t = 3)
        $high = static fn(array $hooks, array $o = []) => [self::pcactn(), self::opts(ctx: ['risk' => self::riskHigh()], o: $o + ['hooks' => $hooks + ['revocation' => self::revOk()]])];
        $s['high risk, no threshold hook'] = static fn() => $high([]);
        $s['high risk, no threshold hook, no budget'] = static function () use ($high) {
            [$p, $o] = $high([]);
            $o['context'] = self::with($o['context'], ['budget' => null]);
            return [$p, $o];
        };
        $s['high risk, threshold t = 2.5'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => 2.5]]);
        $s['high risk, threshold t = 2.9'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => 2.9]]);
        $s['high risk, threshold t = 2'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => 2]]);
        $s['high risk, threshold t = 3'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => 3]]);
        $s['high risk, threshold t = true'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => true]]);
        $s['high risk, threshold unreported'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => true]]);
        $s['high risk, threshold rejected'] = static fn() => $high(['threshold' => static fn() => ['enforced' => true, 'ok' => false]]);
        $s['high risk, threshold without enforced, assurance'] = static fn() => $high(['threshold' => static fn() => ['ok' => true, 't' => 3]], ['assurance' => true]);
        $s['threshold t = 3 with assurance'] = static fn() => [self::pcactn(), self::opts(o: ['assurance' => true, 'hooks' => ['revocation' => self::revOk(),
            'threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => 3]]])];
        // ---- PQ pins
        $pq = static fn(array $set, mixed $pins) => [self::pcactn(), self::opts(o: ['grant' => self::with(self::grant(), $set), 'pqPins' => $pins])];
        $issuer = self::kp(1)->public;
        $s['classical grant, issuer pinned (object)'] = static fn() => $pq([], Obj::of([$issuer => 'PK']));
        $s['classical grant, issuer pinned (array)'] = static fn() => $pq([], [$issuer => 'PK']);
        $s['classical grant, issuer pinned to null'] = static fn() => $pq([], [$issuer => null]);
        $s['classical grant, other issuer pinned'] = static fn() => $pq([], ['someone' => 'PK']);
        $s['pq grant, matching pin'] = static fn() => $pq(['alg' => 'ml-dsa-65', 'pq_pk' => 'PK'], [$issuer => 'PK']);
        $s['pq grant, matching pin (object)'] = static fn() => $pq(['alg' => 'ml-dsa-65', 'pq_pk' => 'PK'], Obj::of([$issuer => 'PK']));
        $s['pq grant, other pin'] = static fn() => $pq(['alg' => 'ml-dsa-65', 'pq_pk' => 'PK'], [$issuer => 'OTHER']);
        $s['pq grant, not pinned'] = static fn() => $pq(['alg' => 'ml-dsa-65', 'pq_pk' => 'PK'], ['someone' => 'PK']);
        $s['pq grant without pq_pk, not pinned'] = static fn() => $pq(['alg' => 'ml-dsa-65'], ['someone' => 'PK']);
        $s['pq grant, numeric suite name, not pinned'] = static fn() => $pq(['alg' => 7, 'pq_pk' => 'PK'], ['someone' => 'PK']);
        // ---- the PCActn and the server plan
        $s['action is not an object'] = static fn() => [self::with(self::pcactn(), ['action' => 'x']), self::opts()];
        $s['plan is not a list'] = static fn() => [self::pcactn(), self::opts(ctx: ['plan' => ['a' => 1]])];
        $s['plan node is not an object'] = static fn() => [self::pcactn(), self::opts(ctx: ['plan' => ['x']])];
        $s['PCActn plan is not an object'] = static fn() => [self::with(self::pcactn(), ['plan' => 'x']), self::opts()];
        $s['revocation epoch of nulls'] = static fn() => [self::pcactn(), self::opts(ctx: ['revocationEpoch' => ['epoch' => ['x' => 1]]])];
        $s['revocation epoch, PCActn freshness not an object'] = static fn() => [self::with(self::pcactn(), ['freshness' => 'x']),
            self::opts(ctx: ['revocationEpoch' => ['epoch' => ['x' => 1], 'lastAcceptedEpoch' => 1, 'maxAgeMs' => 5]])];
        $s['beacon is not an object'] = static fn() => [self::pcactn(), self::opts(ctx: ['beacon' => ['beacon' => 'x', 'issuers' => [], 'lastAcceptedSeq' => 3]])];
        $beacon = static fn(int $seq) => Beacons::issue(Sign::n(['issuerSecret' => str_repeat("\x09", 32), 'instance' => 'i1', 'seq' => $seq, 'issuedAt' => self::NOW - 1000]));
        $s['valid beacon, PCActn freshness not an object'] = static fn() => [self::with(self::pcactn(), ['freshness' => 'x']),
            self::opts(ctx: ['beacon' => ['beacon' => $beacon(5), 'issuers' => [self::kp(9)->public], 'instance' => 'i1']])];
        $s['valid beacon, unbound'] = static fn() => [self::pcactn(), self::opts(ctx: ['beacon' => ['beacon' => $beacon(5), 'issuers' => [self::kp(9)->public], 'instance' => 'i1']])];
        $s['valid beacon, replayed'] = static fn() => [self::pcactn(), self::opts(ctx: ['beacon' => ['beacon' => $beacon(5), 'issuers' => [self::kp(9)->public], 'instance' => 'i1', 'lastAcceptedSeq' => 6]])];
        $s['bad beacon, older seq'] = static fn() => [self::pcactn(), self::opts(ctx: ['beacon' => ['beacon' => $beacon(5), 'issuers' => [], 'instance' => 'i1', 'lastAcceptedSeq' => 6]])];
        $s['grant without an envelope'] = static fn() => [self::pcactn(), self::opts(o: ['grant' => self::with(self::grant(), ['caveats' => []])])];
        // ---- budget, risk inputs, requirements
        $s['budget given as null'] = static fn() => [self::pcactn(), self::opts(ctx: ['budget' => null])];
        $s['no budget'] = static function () {
            $o = self::opts();
            $o['context'] = $o['context']->without('budget');
            return [self::pcactn(), $o];
        };
        $s['required risk input named by a number'] = static fn() => [self::pcactn(), self::opts(o: ['requireRiskInputs' => [5, 'taint']])];
        $s['required risk inputs missing'] = static fn() => [self::pcactn(), self::opts(ctx: ['risk' => ['taint' => 0]], o: ['requireRiskInputs' => ['confidence', 'blastRadius', 'taint']])];
        $s['require is not a list'] = static fn() => [self::pcactn(), self::opts(o: ['require' => 'x'])];
        $s['require names a fractional number'] = static fn() => [self::pcactn(), self::opts(o: ['require' => [1.5, 'policy']])];
        $s['requireAssurance false'] = static fn() => [self::pcactn(), self::opts(o: ['requireAssurance' => false])];
        $s['requireAssurance null'] = static fn() => [self::pcactn(), self::opts(o: ['requireAssurance' => null])];
        $s['requireAssurance as a requirement object'] = static fn() => [self::pcactn(), self::opts(o: ['requireAssurance' => new AssuranceRequirement(signature: 'classical')])];
        $s['requireAssurance as JSON'] = static fn() => [self::pcactn(), self::opts(o: ['requireAssurance' => Obj::of(['signature' => 'classical'])])];
        $s['assurance with every hook'] = static fn() => [self::pcactn(), self::opts(o: ['assurance' => true, 'hooks' => ['revocation' => self::revOk(),
            'attestation' => static fn() => ['enforced' => true, 'ok' => true], 'zk' => static fn() => ['enforced' => true, 'ok' => true],
            'threshold' => static fn() => ['enforced' => true, 'ok' => true, 't' => 1]]])];
        // ---- the chain and delegated caveats
        $s['leaf is not an object'] = static fn() => [self::with(self::pcactn(), ['cap_chain' => ['x']]), self::opts()];
        $s['leaf without a caveat list'] = static fn() => [self::with(self::pcactn(), ['cap_chain' => [self::with(self::grant(), ['caveats' => null])]]), self::opts()];
        $s['empty chain'] = static fn() => [self::with(self::pcactn(), ['cap_chain' => []]), self::opts()];
        $s['delegation depth 0 allowed'] = static function () {
            $g = self::grant(['caveats' => [['type' => 'delegation_depth', 'max' => 0]]]);
            return [self::pcactn($g), self::opts($g)];
        };
        $s['caution as a number'] = static fn() => [self::pcactn(extra: ['caution' => 0.9]), self::opts()];
        $s['caution as a string'] = static fn() => [self::with(self::pcactn(), ['caution' => 'x']), self::opts()];
        $s['tool binding'] = static fn() => [self::pcactn(extra: ['tool_binding' => Pca::b64u(str_repeat("\x05", 32))]), self::opts()];
        $s['reversibility class from the server'] = static fn() => [self::pcactn(), self::opts(ctx: ['reversibilityClass' => 'irreversible'])];
        $s['reversibility class equal rank'] = static fn() => [self::pcactn(), self::opts(ctx: ['reversibilityClass' => 'reversible'])];
        // ---- batch 2: suites, gates, budgets, the plan geodesic, delegated caveats, predicates on subject / env
        $s['allowed suites exclude ed25519'] = static fn() => [self::pcactn(), self::opts(o: ['allowedSuites' => ['ml-dsa-65']])];
        $s['allowed suites include ed25519'] = static fn() => [self::pcactn(), self::opts(o: ['allowedSuites' => ['ed25519']])];
        $s['allowed suites not a list'] = static fn() => [self::pcactn(), self::opts(o: ['allowedSuites' => 'ml-dsa-65'])];
        $s['taint gate passes'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['taint' => ['registry' => null, 'resourceGraph' => null, 'maxTaint' => 1]]])];
        $s['taint gate misconfigured'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['taint' => ['registry' => null, 'resourceGraph' => null, 'maxTaint' => -1]]])];
        $s['taint gate as an object'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => Obj::of(['taint' => Obj::of(['maxTaint' => -1])])])];
        $s['taint gate with a non-object graph'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['taint' => ['registry' => null, 'resourceGraph' => 5, 'maxTaint' => 1]]])];
        $s['freshness enforced (numbers)'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['freshness' => Sign::n(['maxAgeMs' => 1000, 'epochMs' => 500, 'clockSkewMs' => 10])]])];
        $s['freshness enforced (native)'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['freshness' => ['maxAgeMs' => 1000, 'epochMs' => 500, 'clockSkewMs' => 10]]])];
        $s['freshness enforced (float)'] = static fn() => [self::pcactn(), self::opts(o: ['enforce' => ['freshness' => Sign::n(['maxAgeMs' => 1000.5])]])];
        $mid = ['reversibility' => 1, 'blastRadius' => 0.5, 'confidence' => 1, 'semanticDistance' => 0, 'taint' => 0];
        $s['mid risk, budget null'] = static fn() => [self::pcactn(), self::opts(ctx: ['risk' => $mid, 'budget' => null])];
        $s['mid risk, budget'] = static fn() => [self::pcactn(), self::opts(ctx: ['risk' => $mid])];
        $s['mid risk, no budget'] = static function () use ($mid) {
            $o = self::opts(ctx: ['risk' => $mid]);
            $o['context'] = $o['context']->without('budget');
            return [self::pcactn(), $o];
        };
        $s['semantic distance from the plan'] = static fn() => [self::pcactn(), self::opts(ctx: ['risk' => ['reversibility' => 1, 'blastRadius' => 0, 'confidence' => 1, 'taint' => 0]])];
        $s['delegated, no caveats'] = static fn() => self::delegated([]);
        $s['delegated expiry between clock ticks'] = static fn() => self::delegated([['type' => 'expires', 'at' => self::NOW + 0.3]], o: ['now' => self::NOW + 0.5]);
        $s['delegated expiry after the clock'] = static fn() => self::delegated([['type' => 'expires', 'at' => self::NOW + 0.7]], o: ['now' => self::NOW + 0.5]);
        $s['delegated blast radius bound'] = static fn() => self::delegated([['type' => 'max_blast_radius', 'max' => 0.5]]);
        $s['delegated blast radius, no risk input'] = static fn() => self::delegated([['type' => 'max_blast_radius', 'max' => 0.5]], ['risk' => ['reversibility' => 1, 'confidence' => 1, 'semanticDistance' => 0, 'taint' => 0]]);
        $s['delegated reversibility bound'] = static fn() => self::delegated([['type' => 'reversibility_max', 'class' => 'reversible']]);
        $s['delegated rate'] = static fn() => self::delegated([['type' => 'rate', 'max' => 2, 'per_secs' => 60]], ['recentActionTimes' => [self::NOW - 1000]]);
        $s['delegated rate exceeded'] = static fn() => self::delegated([['type' => 'rate', 'max' => 1, 'per_secs' => 60]], ['recentActionTimes' => [self::NOW - 1000]]);
        $s['delegated depth 0'] = static fn() => self::delegated([['type' => 'delegation_depth', 'max' => 0]]);
        $s['delegated depth 1'] = static fn() => self::delegated([['type' => 'delegation_depth', 'max' => 1]]);
        $schema = ['props' => [], 'required' => []];
        $tool = static fn(string $sig) => ['type' => 'tool_schema', 'tool' => 'v', 'schema' => Sign::n($schema), 'schema_digest' => Pca::hashCanonical(Sign::n($schema)),
            'signature_digest' => $sig, 'binding_digest' => Pca::hashCanonical(Sign::n(['tool' => 'v', 'signature_digest' => $sig, 'schema' => $schema]))];
        $tb = Pca::b64u(str_repeat("\x05", 32));
        $s['delegated tool schema, other signature'] = static function () use ($tool, $tb) {
            $g = self::grant();
            $child = Sign::delegate($g, self::kp(2), self::kp(3)->public, [$tool('other')]);
            return [self::pcactn($g, ['tool_binding' => $tb], [$g, $child], signer: 3), self::opts($g)];
        };
        $s['delegated tool schema, bound signature'] = static function () use ($tool, $tb) {
            $g = self::grant();
            $child = Sign::delegate($g, self::kp(2), self::kp(3)->public, [$tool($tb)]);
            return [self::pcactn($g, ['tool_binding' => $tb], [$g, $child], signer: 3), self::opts($g)];
        };
        $s['envelope rate caveat'] = static function () {
            $g = self::grant(['caveats' => [['type' => 'rate', 'max' => 2, 'per_secs' => 60]]]);
            return [self::pcactn($g), self::opts($g, ['recentActionTimes' => [self::NOW - 1000]])];
        };
        $s['envelope depth caveat, empty chain'] = static function () {
            $g = self::grant(['caveats' => [['type' => 'delegation_depth', 'max' => -1]]]);
            return [self::with(self::pcactn($g), ['cap_chain' => []]), self::opts($g)];
        };
        $s['predicate on the subject'] = static function () {
            $g = self::grant(['predicates' => [['verb' => 'v', 'resource' => 'r', 'where' => [['field' => 'subject.id', 'op' => 'exists']]]]]);
            return [self::pcactn($g), self::opts($g, ['subject' => ['id' => 'u1']])];
        };
        $s['predicate on the env'] = static function () {
            $g = self::grant(['predicates' => [['verb' => 'v', 'resource' => 'r', 'where' => [['field' => 'env.region', 'op' => 'exists']]]]]);
            return [self::pcactn($g), self::opts($g, ['env' => ['region' => 'eu']])];
        };
        $s['predicate on a param'] = static function () {
            $g = self::grant(['predicates' => [['verb' => 'v', 'resource' => 'r', 'where' => [['field' => 'action.params.x', 'op' => 'exists']]]]]);
            return [self::pcactn($g), self::opts($g, ['params' => ['x' => 1]])];
        };
        $s['costly declared, rate limited by the server'] = static function () {
            $g = self::grant(['caveats' => [['type' => 'reversibility_max', 'class' => 'rate_limited']]]);
            return [self::pcactn($g, class: 'costly'), self::opts($g, ['plan' => self::plan('costly'), 'reversibilityClass' => 'rate_limited'])];
        };
        $s['rate limited declared, costly by the server'] = static function () {
            $g = self::grant(['caveats' => [['type' => 'reversibility_max', 'class' => 'rate_limited']]]);
            return [self::pcactn($g, class: 'rate_limited'), self::opts($g, ['plan' => self::plan('rate_limited'), 'reversibilityClass' => 'costly'])];
        };
        $s['attestation and threshold hooks both throw'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(),
            'attestation' => static fn() => throw new \RuntimeException('first'), 'threshold' => static fn() => throw new \RuntimeException('second')]])];
        $s['attestation and threshold hooks both answer null'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(),
            'attestation' => static fn() => null, 'threshold' => static fn() => null]])];
        $s['threshold and zk hooks both throw'] = static fn() => [self::pcactn(), self::opts(o: ['hooks' => ['revocation' => self::revOk(),
            'threshold' => static fn() => throw new \RuntimeException('first'), 'zk' => static fn() => throw new \RuntimeException('second')]])];
        $s['leaf suite outside the policy'] = static fn() => [self::with(self::pcactn(), ['alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => Pca::b64u(str_repeat("\x07", 1952)), 'pq_sig' => Pca::b64u(str_repeat("\x07", 3309))]), self::opts(o: ['allowedSuites' => ['ed25519']])];
        $s['leaf PQ suite without a holder commitment'] = static fn() => [self::with(self::pcactn(), ['alg' => 'hybrid-ed25519-ml-dsa-65', 'pq_pk' => Pca::b64u(str_repeat("\x07", 1952)), 'pq_sig' => Pca::b64u(str_repeat("\x07", 3309))]), self::opts()];
        $s['leaf ML-DSA suite outside the policy'] = static fn() => [self::with(self::pcactn(), ['alg' => 'ml-dsa-65']), self::opts(o: ['allowedSuites' => ['ed25519']])];
        // ---- batch 3: the grant's model rules (Intent v2 context without a v2 policy)
        $modelWhere = [['verb' => 'v', 'resource' => 'r', 'where' => [['field' => 'env.class.label', 'op' => 'eq', 'value' => 'ok']]]];
        foreach (['units' => ['units' => Sign::n(['action.params.x' => ['kind' => 'count']])], 'tighten' => ['tighten' => []],
            'polarity legacy' => ['model_polarity' => 'legacy', 'predicates' => $modelWhere], 'polarity alone' => ['model_polarity' => 'legacy'],
            'model path' => ['predicates' => $modelWhere]] as $n => $e) {
            $s["model rules: $n"] = static function () use ($e) {
                $g = self::grant($e);
                return [self::pcactn($g), self::opts($g, ['env' => ['class' => ['label' => 'ok']]])];
            };
            $s["model rules: $n, v2 context"] = static function () use ($e) {
                $g = self::grant($e);
                return [self::pcactn($g), self::opts($g, ['env' => ['class' => ['label' => 'no']]], ['intentV2' => Sign::n(['env' => ['class' => ['label' => 'ok']], 'params' => ['x' => 2]])])];
            };
        }
        $s['intentV2 option without model rules'] = static fn() => [self::pcactn(), self::opts(o: ['intentV2' => Sign::n(['policy' => ['model_polarity' => 'legacy']])])];
        $s['intentV2 option as an array'] = static fn() => [self::pcactn(), self::opts(o: ['intentV2' => ['policy' => ['model_polarity' => 'bad']]])];
        return $s;
    }

    /** @return array<string, array<string,mixed>> */
    public static function observe(): array
    {
        $out = [];
        foreach (self::scenarios() as $name => $make) {
            $r = $make();
            $sum = self::summary(VerifyVerdict::verify($r[0], $r[1]));
            if (isset($r[2])) {
                $sum['observed'] = ($r[2])();
            }
            if ($name === 'the wall clock') {
                unset($sum['budget']); // stamped with the wall clock
            }
            $out[$name] = $sum;
        }
        return $out;
    }

    public function testEveryScenarioKeepsItsVerdict(): void
    {
        $want = self::golden();
        $have = self::observe();
        self::assertSame(array_keys($want), array_keys($have));
        foreach ($want as $name => $w) {
            self::assertSame($w, $have[$name], $name);
        }
    }

    public function testEnforceIsPublic(): void
    {
        $v = VerifyVerdict::enforce(['allow' => true, 'checks' => ['a' => 'pass', 'b' => 'unsupported'], 'reasons' => []], ['a', 'b', 'c']);
        self::assertSame(['allow' => false, 'checks' => ['a' => 'pass', 'b' => 'fail', 'c' => 'fail'], 'reasons' => [
            'b: required check is unsupported (default-deny: not enforced by this resource server)',
            'c: required check is absent (default-deny: not enforced by this resource server)']], $v);
    }

    /** @return array<string, array<string,mixed>> */
    private static function golden(): array
    {
        // GOLDEN-BEGIN
        return [
            'base' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'grant null' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'verifier error (fail closed): the grant is not a capability',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'grant without caveats' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'verifier error (fail closed): the grant is not a capability',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'grant as an array' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'verifier error (fail closed): the grant is not a capability',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'clock NaN, requireAssurance null' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'the verifier clock is not a finite time',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'clock NaN, requireAssurance set' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'the verifier clock is not a finite time',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
                'assurance' => '203aa6ea21ca68d5a95a0a47afe7dfca65d15830',
            ],
            'clock NaN, assurance' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'the verifier clock is not a finite time',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
                'assurance' => '203aa6ea21ca68d5a95a0a47afe7dfca65d15830',
            ],
            'clock 2^53 - 1' => [
                'allow' => false,
                'r' => 0.05,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'validity: the PCActn has expired',
                    'policy: trust budget depleted: human recharge required',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'validity' => 'fail',
                    'threshold' => 'fail',
                ],
            ],
            'clock 2^53' => [
                'allow' => false,
                'r' => 0.05,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'validity: the verifier clock is not a safe integer epoch-ms',
                    'policy: trust budget depleted: human recharge required',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'validity' => 'fail',
                    'threshold' => 'fail',
                ],
            ],
            'clock with a fraction' => [
                'allow' => false,
                'r' => 6.944444444444444E-9,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'validity: the verifier clock is not a safe integer epoch-ms',
                ],
                'checks' => [
                    'validity' => 'fail',
                ],
            ],
            'clock with a fraction, bad signature' => [
                'allow' => false,
                'r' => 6.944444444444444E-9,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'validity: the verifier clock is not a safe integer epoch-ms',
                ],
                'checks' => [
                    'validity' => 'fail',
                    'leaf_signature' => 'fail',
                ],
            ],
            'clock as an integral float' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'hook context under an unsafe clock' => [
                'allow' => false,
                'r' => 6.944444444444444E-9,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'validity: the verifier clock is not a safe integer epoch-ms',
                ],
                'checks' => [
                    'validity' => 'fail',
                ],
                'observed' => [
                    'keys' => [
                        'pcactn',
                        'grant',
                        'nowEpoch',
                    ],
                    'nowEpoch' => 0,
                    'pcactn' => true,
                ],
            ],
            'the wall clock' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge',
                ],
                'checks' => [
                    'budget' => 'not-enforced',
                ],
            ],
            'context as an associative array' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'operation as an array' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'operation' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'operation for another verb' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'operation: the proof is for v on r, but this operation is w on r',
                ],
                'checks' => [
                    'operation' => 'fail',
                ],
            ],
            'operation as an empty array' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'hooks as an object' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'attestation gate as an object' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'attestation: attestation required but the verifier reported not-enforced / no document (fail closed)',
                ],
                'checks' => [
                    'attestation' => 'fail',
                ],
            ],
            'attestation gate as an array' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'attestation: attestation required but the verifier reported not-enforced / no document (fail closed)',
                ],
                'checks' => [
                    'attestation' => 'fail',
                ],
            ],
            'attestation gate not required' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'lifetime too long' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'validity: lifetime exceeds 3600000 ms',
                ],
                'checks' => [
                    'validity' => 'fail',
                ],
            ],
            'version with a newline' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'ver\' must be a safe integer',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'attestation and zk hooks both throw' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: first',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'attestation' => NULL,
                    'threshold' => NULL,
                ],
            ],
            'attestation and zk hooks both answer null' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: Cannot read properties of null (reading \'enforced\')',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'attestation' => NULL,
                    'threshold' => NULL,
                ],
            ],
            'attestation hook answers a string' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'revocation hook answers nothing' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'revocation: required check is not-enforced (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'revocation' => 'fail',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'revocation hook enforces without ok' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'revocation: rejected',
                ],
                'checks' => [
                    'revocation' => 'fail',
                ],
            ],
            'revocation hook answers a string' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'revocation: required check is not-enforced (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'revocation' => 'fail',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'revocation hook throws' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: rev',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                ],
            ],
            'threshold hook throws' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: thr',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'threshold' => NULL,
                ],
            ],
            'attestation throws after a threshold refusal' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: att',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'attestation' => NULL,
                    'threshold' => NULL,
                ],
            ],
            'revocation throws after a threshold refusal' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'threshold: no',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'threshold' => 'fail',
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                ],
            ],
            'zk refusal then revocation throws' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: rev',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                ],
            ],
            'high risk, no threshold hook' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, no threshold hook, no budget' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge',
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                    'budget' => 'not-enforced',
                ],
            ],
            'high risk, threshold t = 2.5' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: threshold hook enforced t=2.5 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, threshold t = 2.9' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: threshold hook enforced t=2.9 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, threshold t = 2' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: threshold hook enforced t=2 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, threshold t = 3' => [
                'allow' => true,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                ],
                'checks' => [
                    'threshold' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'high risk, threshold t = true' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: threshold hook enforced t=true but the server requires t=3 (below the server-derived threshold; derive t from server-held data)',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, threshold unreported' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: threshold hook enforced t=unreported but the server requires t=3 (below the server-derived threshold; derive t from server-held data)',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, threshold rejected' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'threshold: rejected',
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: t=3 required and the threshold proof was rejected',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'high risk, threshold without enforced, assurance' => [
                'allow' => false,
                'r' => 0.9500000000000001,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.950 exceeds auto threshold: step-up to t=3',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
                'assurance' => 'df3c1b891d9d89b0d1975dfd2efcdfa751d827a4',
            ],
            'threshold t = 3 with assurance' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'threshold' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
                'assurance' => '2cd8896dcbbe6031c0d9c16aa03cd90a05253be2',
            ],
            'classical grant, issuer pinned (object)' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused',
                ],
                'checks' => [
                    'pq_pin' => 'fail',
                ],
            ],
            'classical grant, issuer pinned (array)' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused',
                ],
                'checks' => [
                    'pq_pin' => 'fail',
                ],
            ],
            'classical grant, issuer pinned to null' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused',
                ],
                'checks' => [
                    'pq_pin' => 'fail',
                ],
            ],
            'classical grant, other issuer pinned' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'pq_pin' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'pq grant, matching pin' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'policy: capability chain unverified: hop 0: body digest mismatch',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'pq_pin' => 'pass',
                    'policy' => 'fail',
                ],
            ],
            'pq grant, matching pin (object)' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'policy: capability chain unverified: hop 0: body digest mismatch',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'pq_pin' => 'pass',
                    'policy' => 'fail',
                ],
            ],
            'pq grant, other pin' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'pq_pin: the grant pq_pk does not match the server-side pin',
                    'policy: capability chain unverified: hop 0: root suite \'ml-dsa-65\': the server-side PQ pin for the root issuer (policy.pqPins) does not match the stored grant\'s pq_pk (fail closed)',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'pq_pin' => 'fail',
                    'policy' => 'fail',
                ],
            ],
            'pq grant, not pinned' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'pq_pin: no server-side PQ pin for the grant issuer (suite ml-dsa-65)',
                    'policy: capability chain unverified: hop 0: body digest mismatch',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'pq_pin' => 'fail',
                    'policy' => 'fail',
                ],
            ],
            'pq grant without pq_pk, not pinned' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'pq_pin: no server-side PQ pin for the grant issuer (suite ml-dsa-65)',
                    'policy: capability chain unverified: hop 0: root suite \'ml-dsa-65\' needs a PQ key pinned for the root issuer (policy.pqPins) or the verifier\'s stored grant (policy.trustedRoot); the root\'s own pq_pk proves nothing about who issued it (R3-01)',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'pq_pin' => 'fail',
                    'policy' => 'fail',
                ],
            ],
            'pq grant, numeric suite name, not pinned' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'pq_pin: no server-side PQ pin for the grant issuer (suite 7)',
                    'policy: capability chain unverified: hop 0: malformed capability',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'pq_pin' => 'fail',
                    'policy' => 'fail',
                ],
            ],
            'action is not an object' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'action\' must be an object',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'plan is not a list' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'verifier error (fail closed): ctx.plan.map is not a function',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'plan node is not an object' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'verifier error (fail closed): plan node is not an object',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'PCActn plan is not an object' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'plan\' must be an object',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'revocation epoch of nulls' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'freshness: malformed revocation epoch',
                ],
                'checks' => [
                    'freshness' => 'fail',
                ],
            ],
            'revocation epoch, PCActn freshness not an object' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'freshness\' is malformed',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'beacon is not an object' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'beacon: malformed beacon',
                ],
                'checks' => [
                    'beacon' => 'fail',
                ],
            ],
            'valid beacon, PCActn freshness not an object' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'freshness\' is malformed',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'valid beacon, unbound' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'beacon: PCActn freshness.beacon_ref does not bind the presented beacon',
                ],
                'checks' => [
                    'beacon' => 'fail',
                ],
            ],
            'valid beacon, replayed' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'beacon: beacon seq 5 is older than the last accepted 6 (replay)',
                ],
                'checks' => [
                    'beacon' => 'fail',
                ],
            ],
            'bad beacon, older seq' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'beacon: issuer not pinned',
                ],
                'checks' => [
                    'beacon' => 'fail',
                ],
            ],
            'grant without an envelope' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'cap_chain: chain root is not the grant',
                    'delegated_caveats: delegation caveat(s) not satisfied: envelope',
                    'policy: grant carries no valid envelope',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'delegated_caveats' => 'fail',
                    'policy' => 'fail',
                ],
            ],
            'budget given as null' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'budget' => 'not-enforced',
                ],
            ],
            'no budget' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge',
                ],
                'checks' => [
                    'budget' => 'not-enforced',
                ],
            ],
            'required risk input named by a number' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'risk_inputs: required risk input(s) not supplied by the server: 5',
                ],
                'checks' => [
                    'risk_inputs' => 'fail',
                ],
            ],
            'required risk inputs missing' => [
                'allow' => false,
                'r' => 0.75,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'risk_inputs: required risk input(s) not supplied by the server: confidence, blastRadius',
                    'policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, confidence',
                    'policy: risk 0.750 exceeds auto threshold: step-up to t=3',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                    'risk_inputs' => 'fail',
                ],
            ],
            'require is not a list' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'verifier error (fail closed): required.map is not a function',
                ],
                'checks' => [
                    'malformed' => 'fail',
                ],
            ],
            'require names a fractional number' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    '1.5: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    '1.5' => 'fail',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'requireAssurance false' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
                'assurance' => 'e5e49ce23258eca0ff828fcaf23a979b5fb3a933',
            ],
            'requireAssurance null' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'requireAssurance as a requirement object' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'assurance: unknown signature requirement "classical" (fail closed)',
                ],
                'checks' => [
                    'assurance' => 'fail',
                ],
                'assurance' => '4b301923e287d6199ec2a88c324a68207bdc180e',
            ],
            'requireAssurance as JSON' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'assurance: unknown signature requirement "classical" (fail closed)',
                ],
                'checks' => [
                    'assurance' => 'fail',
                ],
                'assurance' => '4b301923e287d6199ec2a88c324a68207bdc180e',
            ],
            'assurance with every hook' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'attestation' => 'pass',
                    'threshold' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
                'assurance' => '50ba3095df2e85b814d25429f6ad4adc4a5e9d55',
            ],
            'leaf is not an object' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: cap_chain[0] must be an object',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'leaf without a caveat list' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: cap_chain[0].caveats must be an array of {type,...} objects',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'empty chain' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'cap_chain: empty chain',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'grant_ref_bound' => 'fail',
                    'leaf_signature' => 'fail',
                    'delegated_caveats' => NULL,
                ],
            ],
            'delegation depth 0 allowed' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'caution as a number' => [
                'allow' => false,
                'r' => 0.9,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: risk 0.900 exceeds auto threshold: step-up to t=3',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                ],
            ],
            'caution as a string' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'caution\' must be a number in [0,1]',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'tool binding' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'reversibility class from the server' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/strict',
                'reasons' => [
                    'reversibility: declared class \'reversible\' is less restrictive than the authoritative \'irreversible\'',
                ],
                'checks' => [
                    'reversibility' => 'fail',
                ],
            ],
            'reversibility class equal rank' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'reversibility' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'allowed suites exclude ed25519' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'cap_chain: hop 0: signature suite \'ed25519\' is not allowed by this verifier\'s suite policy',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'leaf_signature' => 'fail',
                ],
            ],
            'allowed suites include ed25519' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'allowed suites not a list' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'taint gate passes' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'taint_gate: taint: no trusted-input registry',
                ],
                'checks' => [
                    'taint_gate' => 'fail',
                ],
            ],
            'taint gate misconfigured' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'taint_gate: taint: no trusted-input registry',
                ],
                'checks' => [
                    'taint_gate' => 'fail',
                ],
            ],
            'taint gate as an object' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'taint_gate: taint: no trusted-input registry',
                ],
                'checks' => [
                    'taint_gate' => 'fail',
                ],
            ],
            'taint gate with a non-object graph' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'taint_gate: taint gate error (fail closed): Atlas\\Pca\\Taint::taintGate(): Argument #3 ($graph) must be of type ?object, int given',
                ],
                'checks' => [
                    'taint_gate' => 'fail',
                ],
            ],
            'freshness enforced (numbers)' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)',
                ],
                'checks' => [
                    'freshness' => 'fail',
                ],
            ],
            'freshness enforced (native)' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)',
                ],
                'checks' => [
                    'freshness' => 'fail',
                ],
            ],
            'freshness enforced (float)' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'freshness: freshness anchor is missing (empty beacon_ref or non-positive epoch stub)',
                ],
                'checks' => [
                    'freshness' => 'fail',
                ],
            ],
            'mid risk, budget null' => [
                'allow' => false,
                'r' => 0.1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'policy: trust budget depleted: human recharge required',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                    'budget' => 'not-enforced',
                ],
            ],
            'mid risk, budget' => [
                'allow' => true,
                'r' => 0.1,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":0.9,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'mid risk, no budget' => [
                'allow' => false,
                'r' => 0.1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'budget: no budget supplied — fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge',
                    'policy: trust budget depleted: human recharge required',
                    'threshold: t=3 (strong) required but no threshold verifier is enforced',
                ],
                'checks' => [
                    'threshold' => 'fail',
                    'budget' => 'not-enforced',
                ],
            ],
            'semantic distance from the plan' => [
                'allow' => true,
                'r' => 0.25,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":0.75,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'delegated, no caveats' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'delegated expiry between clock ticks' => [
                'allow' => false,
                'r' => 6.944444444444444E-9,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'validity: the verifier clock is not a safe integer epoch-ms',
                    'delegated_caveats: delegation caveat(s) not satisfied: expires',
                ],
                'checks' => [
                    'validity' => 'fail',
                    'delegated_caveats' => 'fail',
                ],
            ],
            'delegated expiry after the clock' => [
                'allow' => false,
                'r' => 6.944444444444444E-9,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'validity: the verifier clock is not a safe integer epoch-ms',
                ],
                'checks' => [
                    'validity' => 'fail',
                ],
            ],
            'delegated blast radius bound' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'delegated blast radius, no risk input' => [
                'allow' => false,
                'r' => 0.2,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'delegated_caveats: delegation caveat(s) not satisfied: max_blast_radius',
                    'policy: risk input(s) missing, assumed worst case: blastRadius',
                ],
                'checks' => [
                    'delegated_caveats' => 'fail',
                ],
            ],
            'delegated reversibility bound' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'delegated rate' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'delegated rate exceeded' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'delegated_caveats: delegation caveat(s) not satisfied: rate',
                ],
                'checks' => [
                    'delegated_caveats' => 'fail',
                ],
            ],
            'delegated depth 0' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'delegated_caveats: delegation caveat(s) not satisfied: delegation_depth',
                ],
                'checks' => [
                    'delegated_caveats' => 'fail',
                ],
            ],
            'delegated depth 1' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'delegated tool schema, other signature' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'delegated_caveats: delegation caveat(s) not satisfied: tool_schema',
                ],
                'checks' => [
                    'delegated_caveats' => 'fail',
                ],
            ],
            'delegated tool schema, bound signature' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'delegated_caveats: delegation caveat(s) not satisfied: tool_schema',
                ],
                'checks' => [
                    'delegated_caveats' => 'fail',
                ],
            ],
            'envelope rate caveat' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'envelope depth caveat, empty chain' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'cap_chain: empty chain',
                    'policy: caveat(s) not satisfied: delegation_depth',
                ],
                'checks' => [
                    'cap_chain' => 'fail',
                    'grant_ref_bound' => 'fail',
                    'leaf_signature' => 'fail',
                    'policy' => 'fail',
                    'delegated_caveats' => NULL,
                ],
            ],
            'predicate on the subject' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'predicate on the env' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'predicate on a param' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'params_digest: supplied params do not hash to action.params_digest',
                ],
                'checks' => [
                    'params_digest' => 'fail',
                ],
            ],
            'costly declared, rate limited by the server' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'reversibility' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'rate limited declared, costly by the server' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'policy: caveat(s) not satisfied: reversibility_max',
                ],
                'checks' => [
                    'reversibility' => 'pass',
                    'policy' => 'fail',
                ],
            ],
            'attestation and threshold hooks both throw' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: first',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'attestation' => NULL,
                    'threshold' => NULL,
                ],
            ],
            'attestation and threshold hooks both answer null' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: Cannot read properties of null (reading \'enforced\')',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'attestation' => NULL,
                    'threshold' => NULL,
                ],
            ],
            'threshold and zk hooks both throw' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'malformed PCActn: first',
                    'revocation: required check is absent (default-deny: not enforced by this resource server)',
                ],
                'checks' => [
                    'malformed' => 'fail',
                    'revocation' => 'fail',
                    'threshold' => NULL,
                ],
            ],
            'leaf suite outside the policy' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'leaf_signature: signature suite \'hybrid-ed25519-ml-dsa-65\' is not allowed by this verifier\'s suite policy',
                ],
                'checks' => [
                    'leaf_signature' => 'fail',
                ],
            ],
            'leaf PQ suite without a holder commitment' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'leaf_signature: suite \'hybrid-ed25519-ml-dsa-65\' needs a PQ key bound to the signer, but the signer\'s holder carries no holder_pq commitment (unbound PQ keys are rejected; F-2)',
                ],
                'checks' => [
                    'leaf_signature' => 'fail',
                ],
            ],
            'leaf ML-DSA suite outside the policy' => [
                'allow' => false,
                'r' => 1,
                'threshold' => '3/strong/strict',
                'reasons' => [
                    'wire: \'sig\' is not canonical base64url (3309 bytes) for alg \'ml-dsa-65\'',
                ],
                'checks' => [
                    'wire' => 'fail',
                    'malformed' => 'fail',
                ],
            ],
            'model rules: units' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'units: this verifier has no action schema configured',
                ],
                'checks' => [
                    'units' => 'fail',
                ],
            ],
            'model rules: units, v2 context' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'units: this verifier has no action schema configured',
                ],
                'checks' => [
                    'units' => 'fail',
                ],
            ],
            'model rules: tighten' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'tighten' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'model rules: tighten, v2 context' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'tighten' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'model rules: polarity legacy' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'tighten' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'model rules: polarity legacy, v2 context' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'policy: env.class.label == "ok" not satisfied for v on r',
                ],
                'checks' => [
                    'tighten' => 'pass',
                    'policy' => 'fail',
                ],
            ],
            'model rules: polarity alone' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'tighten' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'model rules: polarity alone, v2 context' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'tighten' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'model rules: model path' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'tighten: a grant\'s where reads model-derived path(s) env.class.label: a model may only tighten (move them into tighten[]) (rule 21)',
                ],
                'checks' => [
                    'tighten' => 'fail',
                ],
            ],
            'model rules: model path, v2 context' => [
                'allow' => false,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [
                    'tighten: a grant\'s where reads model-derived path(s) env.class.label: a model may only tighten (move them into tighten[]) (rule 21)',
                    'policy: env.class.label == "ok" not satisfied for v on r',
                ],
                'checks' => [
                    'tighten' => 'fail',
                    'policy' => 'fail',
                ],
            ],
            'intentV2 option without model rules' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [
                    'tighten' => 'pass',
                ],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
            'intentV2 option as an array' => [
                'allow' => true,
                'r' => 0.0,
                'threshold' => '1/claim/optimistic',
                'reasons' => [],
                'checks' => [],
                'budget' => '{"B":1,"tau":1791288000000,"asOf":1791288000000}',
            ],
        ];
        // GOLDEN-END
    }
}
