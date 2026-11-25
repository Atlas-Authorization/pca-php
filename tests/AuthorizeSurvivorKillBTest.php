<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Beacons;
use Atlas\Pca\BudgetStateStore;
use Atlas\Pca\ClaimResult;
use Atlas\Pca\InMemoryTaintRegistry;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RevocationState;
use Atlas\Pca\RevocationStaleness;
use Atlas\Pca\RevocationStalenessPolicy;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * Authorize::authorize after the core verdict (the revocation epoch pin, the server-side PQ pin, the taint gate, the liveness beacon,
 * the durable contract, the risk hook, the threshold hook, the pin and budget claims): the core verdict is replaced through the
 * Authorize::$coreHook seam so every post-core branch is pinned by its exact check status and reason.
 */
final class AuthorizeSurvivorKillBTest extends TestCase
{
    private const CORE = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature',
        'counter_format'];

    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;
    private int $now;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->grant = $c->get('grant');
                $this->p = $c->get('steps')[0]->get('pcactn');
                $this->op = $c->get('steps')[0]->get('operation');
            }
        }
        $this->now = $this->fix->get('now')->int();
        self::core();
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    /** Replace the core verdict: every core check passes, except `$over` (false = fails). */
    private static function core(array $over = []): void
    {
        Authorize::$coreHook = static function (array $c) use ($over): array {
            $checks = array_fill_keys(self::CORE, true);
            foreach ($over as $k => $v) {
                $checks[$k] = $v;
            }
            return ['allow' => !in_array(false, $checks, true), 'checks' => $checks, 'reason' => '', 'reasons' => []];
        };
    }

    private static function copy(Obj $o): Obj
    {
        return Json::parseLax(Json::canonicalizeStrict($o));
    }

    private function p(): Obj
    {
        return self::copy($this->p);
    }

    private function gid(): string
    {
        return $this->grant->get('id');
    }

    /** authorize() over the base fixture; `$o` overrides any named argument (plus `grant`). */
    private function az(array $o = []): AuthorizeResult
    {
        $op = $o['operation'] ?? $this->op;
        $g = $o['grant'] ?? $this->grant;
        unset($o['grant']);
        $base = ['pcactn' => $this->p(), 'operation' => $op, 'audience' => $this->fix->get('audience'), 'resolveGrant' => static fn($ref) => $g,
            'stateStore' => new MemoryStateStore(), 'isRevoked' => static fn() => false, 'now' => $this->now, 'plan' => 'single-step',
            'provenance' => ProvHarness::bundle($op), 'provenanceMediators' => [ProvHarness::pin()], 'hard' => CalmRisk::hard()];
        return Authorize::authorize(...array_merge($base, $o));
    }

    /** A replay store that records the pins it is asked to raise; `$mode` is '', 'pin-throws' or 'raise-throws'. */
    private static function recStore(array $pins = [], string $mode = ''): object
    {
        return new class ($pins, $mode) {
            /** @var list<array{0:string,1:mixed}> */
            public array $raised = [];

            public function __construct(public array $pins, private string $mode)
            {
            }

            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }

            public function pin(string $key): mixed
            {
                if ($this->mode === 'pin-throws') {
                    throw new \RuntimeException('down');
                }
                return $this->pins[$key] ?? null;
            }

            public function raisePin(string $key, mixed $value): void
            {
                if ($this->mode === 'raise-throws') {
                    throw new \RuntimeException('down');
                }
                $this->raised[] = [$key, $value];
                $this->pins[$key] = $value;
            }
        };
    }

    // ---- the revocation epoch pin -------------------------------------------------------------------------------------------

    private static function seed(): string
    {
        return str_repeat("\x0d", 32);
    }

    private function guardian(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())));
    }

    private function epoch(int $n): Obj
    {
        return RevocationStaleness::signEpoch(self::seed(), ['instance_id' => 'i', 'grant_ref' => $this->gid(), 'epoch' => $n, 'set_size' => 0,
            'root' => 'r', 'issued_at' => $this->now - 1000, 'not_after' => $this->now + 1000000]);
    }

    private static function policy(bool $allowUnsignedRoot = false): RevocationStalenessPolicy
    {
        return new RevocationStalenessPolicy(1000000.0, null, $allowUnsignedRoot, static fn() => []);
    }

    /** One authorize() call with revocation staleness on; the PCActn anchors its freshness to `$epoch`. */
    private function epochAz(object $store, int $epoch, ?RevocationState $state = null): AuthorizeResult
    {
        $p = $this->p();
        $p->get('freshness')->set('epoch', new Num((string)$epoch));
        $state ??= new RevocationState($this->epoch($epoch));
        return $this->az(['pcactn' => $p, 'stateStore' => $store, 'revocationStaleness' => self::policy(),
            'revocationState' => static fn() => $state, 'guardianPublic' => $this->guardian()]);
    }

    public function testAPinStoredForTheGrantDoesNotInventARevocationState(): void
    {
        $store = new MemoryStateStore();
        $store->raisePin($this->gid() . ':epoch', 5);
        $r = $this->az(['stateStore' => $store, 'revocationStaleness' => self::policy(), 'revocationState' => static fn() => null,
            'guardianPublic' => $this->guardian()]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains('freshness: no verifiable (guardian-signed) revocation state for an irreversible action', $r->reasons);
    }

    public function testAPinStoreThatCannotBeReadIsAStateSourceFailure(): void
    {
        $r = $this->epochAz(self::recStore([], 'pin-throws'), 5);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains('freshness: the revocation state source failed (fail closed)', $r->reasons);
    }

    public function testAStoredPinBeatsALowerHostPin(): void
    {
        $store = new MemoryStateStore();
        $store->raisePin($this->gid() . ':epoch', 5);
        $r = $this->epochAz($store, 4, new RevocationState($this->epoch(4), null, null, 3.0));
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains('freshness: revocation epoch 4 is older than the last accepted 5 (rollback)', $r->reasons);
        $this->assertSame(5, $store->pin($this->gid() . ':epoch'));
    }

    public function testAPinReadAsANumericStringIsStillComparedAndKept(): void
    {
        $store = self::recStore([$this->gid() . ':epoch' => '5']);
        $r = $this->epochAz($store, 7);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['freshness']);
        $this->assertSame([[$this->gid() . ':epoch', 7]], $store->raised);
        // and the string pin is a rollback guard: epoch 4 is older than 5
        $store = self::recStore([$this->gid() . ':epoch' => '5']);
        $r = $this->epochAz($store, 4);
        $this->assertFalse($r->allow);
        $this->assertContains('freshness: revocation epoch 4 is older than the last accepted 5 (rollback)', $r->reasons);
        $this->assertSame([], $store->raised);
    }

    public function testAnAdmittedSignedEpochRaisesThePinOnce(): void
    {
        $store = self::recStore();
        $r = $this->epochAz($store, 5);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame([[$this->gid() . ':epoch', 5]], $store->raised);
    }

    public function testARootOnlyStateAdmitsAndRaisesNoPin(): void
    {
        $store = self::recStore();
        $state = new RevocationState(null, 'r', (float)($this->now - 1000));
        $r = $this->az(['stateStore' => $store, 'revocationStaleness' => self::policy(true), 'revocationState' => static fn() => $state]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['freshness']);
        $this->assertSame([], $store->raised);
    }

    public function testAPinStoreThatCannotRaiseDeniesWithItsOwnReason(): void
    {
        $r = $this->epochAz(self::recStore([], 'raise-throws'), 5);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertContains('freshness: the revocation pin store failed (fail closed)', $r->reasons);
    }

    // ---- the server-side PQ pin ---------------------------------------------------------------------------------------------

    private function pqGrant(?string $alg, ?string $pk): Obj
    {
        $g = self::copy($this->grant);
        if ($alg !== null) {
            $g->set('alg', $alg);
        }
        if ($pk !== null) {
            $g->set('pq_pk', $pk);
        }
        return $g;
    }

    /** @return list<array{0:string,1:mixed}> the same pin map as a PHP array and as an Obj */
    private function pinForms(array $pins): array
    {
        return [['array', $pins], ['obj', Obj::of($pins)]];
    }

    public function testAnUnpinnedIssuerPassesAClassicalGrant(): void
    {
        foreach ($this->pinForms(['someone-else' => 'PK']) as [$form, $pins]) {
            $r = $this->az(['pqPins' => $pins]);
            $this->assertSame('pass', $r->checks['pq_pin'] ?? 'absent', $form);
            $this->assertTrue($r->allow, $form . ': ' . implode('; ', $r->reasons));
        }
    }

    public function testAPinnedIssuerRefusesAClassicalGrant(): void
    {
        $issuer = $this->grant->get('issuer');
        foreach ($this->pinForms([$issuer => 'PK']) as [$form, $pins]) {
            $r = $this->az(['pqPins' => $pins]);
            $this->assertFalse($r->allow, $form);
            $this->assertSame('fail', $r->checks['pq_pin'] ?? 'absent', $form);
            $this->assertContains('pq_pin: the grant issuer is pinned to a post-quantum key; a classical grant is refused', $r->reasons, $form);
        }
    }

    public function testAPostQuantumGrantNeedsItsOwnPin(): void
    {
        $issuer = $this->grant->get('issuer');
        $g = $this->pqGrant('ml-dsa-65', 'PK');
        foreach ($this->pinForms([$issuer => 'PK']) as [$form, $pins]) {
            $r = $this->az(['grant' => $g, 'pqPins' => $pins]);
            $this->assertSame('pass', $r->checks['pq_pin'] ?? 'absent', $form);
        }
        foreach ($this->pinForms([$issuer => 'OTHER']) as [$form, $pins]) {
            $r = $this->az(['grant' => $g, 'pqPins' => $pins]);
            $this->assertSame('fail', $r->checks['pq_pin'] ?? 'absent', $form);
            $this->assertContains('pq_pin: the grant pq_pk does not match the server-side pin', $r->reasons, $form);
        }
        foreach ($this->pinForms(['someone-else' => 'PK']) as [$form, $pins]) {
            $r = $this->az(['grant' => $g, 'pqPins' => $pins]);
            $this->assertSame('fail', $r->checks['pq_pin'] ?? 'absent', $form);
            $this->assertContains('pq_pin: no server-side PQ pin for the grant issuer (suite ' . IntentWb::jsStr('ml-dsa-65') . ')', $r->reasons, $form);
        }
        // a pin that is not a string, or a grant without pq_pk, never matches
        foreach ($this->pinForms([$issuer => 5]) as [$form, $pins]) {
            $r = $this->az(['grant' => $g, 'pqPins' => $pins]);
            $this->assertSame('fail', $r->checks['pq_pin'] ?? 'absent', $form);
        }
        foreach ($this->pinForms([$issuer => 'PK']) as [$form, $pins]) {
            $r = $this->az(['grant' => $this->pqGrant('ml-dsa-65', null), 'pqPins' => $pins]);
            $this->assertSame('fail', $r->checks['pq_pin'] ?? 'absent', $form);
            $this->assertContains('pq_pin: the grant pq_pk does not match the server-side pin', $r->reasons, $form);
        }
    }

    // ---- the taint gate -----------------------------------------------------------------------------------------------------

    public function testTheTaintGateRefusesAndPasses(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('a')->recordTool('t', 'x');
        $p = $this->p();
        $p->set('provenance', Obj::of(['trusted_refs' => ['a', 't']]));
        $r = $this->az(['pcactn' => $p, 'hard' => CalmRisk::hard(['enforceTaint' => ['registry' => $reg, 'maxTaint' => 0.25]])]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['taint_gate']);
        $this->assertContains('taint_gate: information-flow taint 0.5 exceeds policy max 0.25', $r->reasons);
        $r = $this->az(['pcactn' => $p, 'hard' => CalmRisk::hard(['enforceTaint' => ['registry' => $reg, 'maxTaint' => 0.5]])]);
        $this->assertSame('pass', $r->checks['taint_gate']);
        $this->assertNotContains('taint_gate: information-flow taint 0.5 exceeds policy max 0.25', $r->reasons);
    }

    // ---- the liveness beacon ------------------------------------------------------------------------------------------------

    private function beacon(KeyPair $kp, int $seq, string $scope = '*'): Obj
    {
        $iat = $this->now - 1000;
        return Sign::signArtifact(Beacons::DOMAIN, [
            'v' => 2, 'instance' => 'inst', 'scope' => $scope, 'epoch' => intdiv($iat, 60000), 'seq' => $seq,
            'issued_at' => $iat, 'not_after' => $iat + 300000, 'issuer' => $kp->public,
        ], $kp);
    }

    /** A PCActn whose freshness binds `$b`. */
    private function bound(?Obj $b): Obj
    {
        $p = $this->p();
        $p->get('freshness')->set('beacon_ref', $b === null ? '' : Beacons::beaconRef($b));
        return $p;
    }

    private static function cfg(KeyPair $kp, Obj $b, string $instance = 'inst'): array
    {
        return ['beacon' => $b, 'issuers' => [$kp->public], 'instance' => $instance];
    }

    private function bz(Obj $p, mixed $beacon, object $store): AuthorizeResult
    {
        return $this->az(['pcactn' => $p, 'stateStore' => $store, 'hard' => CalmRisk::hard(['beacon' => $beacon])]);
    }

    private const NOT_ENFORCED = 'beacon: required check is not-enforced (default-deny: not enforced by this resource server)';

    public function testABeaconInArrayFormPassesAndRaisesItsPin(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 7);
        $store = self::recStore();
        $r = $this->bz($this->bound($b), self::cfg($kp, $b), $store);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['beacon']);
        $this->assertSame([[$this->gid() . ':beacon', 7]], $store->raised);
    }

    public function testABeaconInCallableFormGetsTheGrantRefAndThePcactn(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 3);
        $seen = [];
        $fn = static function (string $ref, Obj $pc) use (&$seen, $kp, $b): array {
            $seen[] = [$ref, $pc];
            return self::cfg($kp, $b);
        };
        $store = self::recStore();
        $r = $this->bz($this->bound($b), $fn, $store);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['beacon']);
        $this->assertCount(1, $seen);
        $this->assertSame($this->p->get('grant_ref'), $seen[0][0]);
        $this->assertSame($this->p->get('grant_ref'), $seen[0][1]->get('grant_ref'));
        // a callable that throws is an unavailable beacon
        $r = $this->bz($this->bound($b), static function (): array {
            throw new \RuntimeException('down');
        }, self::recStore());
        $this->assertFalse($r->allow);
        $this->assertContains(self::NOT_ENFORCED, $r->reasons);
    }

    public function testAMalformedBeaconConfigurationIsNotEnforcedAndDenied(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 1);
        $pk = $kp->public;
        $cases = [
            'beacon not an object' => ['beacon' => 'junk', 'instance' => 'inst', 'issuers' => [$pk]],
            'instance not a string' => ['beacon' => $b, 'instance' => 5, 'issuers' => [$pk]],
            'issuers not a list' => ['beacon' => $b, 'instance' => 'inst', 'issuers' => $pk],
            'only issuers valid' => ['beacon' => 'junk', 'instance' => 5, 'issuers' => [$pk]],
            'only beacon valid' => ['beacon' => $b, 'instance' => 5, 'issuers' => $pk],
            'only instance valid' => ['beacon' => 'junk', 'instance' => 'inst', 'issuers' => $pk],
            'nothing valid' => ['beacon' => 'junk', 'instance' => 5, 'issuers' => $pk],
            'not an array at all' => new \ArrayObject(['beacon' => $b, 'instance' => 'inst', 'issuers' => [$pk]]),
            'a callable returning null' => static fn(): mixed => null,
        ];
        foreach ($cases as $name => $cfg) {
            $r = $this->bz($this->bound($b), $cfg, self::recStore());
            $this->assertFalse($r->allow, $name);
            $this->assertSame('fail', $r->checks['beacon'], $name);
            $this->assertContains(self::NOT_ENFORCED, $r->reasons, $name);
        }
    }

    public function testABeaconSeqBelowTheStoredPinIsAReplay(): void
    {
        $kp = KeyPair::generate();
        $key = $this->gid() . ':beacon';
        $b = $this->beacon($kp, 4);
        $store = self::recStore([$key => 5]);
        $r = $this->bz($this->bound($b), self::cfg($kp, $b), $store);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['beacon']);
        $this->assertContains('beacon: beacon seq 4 is older than the last accepted 5 (replay)', $r->reasons);
        $this->assertSame([], $store->raised);
    }

    public function testABeaconSeqAtOrAboveTheStoredPinIsAccepted(): void
    {
        $kp = KeyPair::generate();
        $key = $this->gid() . ':beacon';
        foreach ([5, 6] as $seq) {
            $b = $this->beacon($kp, $seq);
            $store = self::recStore([$key => 5]);
            $r = $this->bz($this->bound($b), self::cfg($kp, $b), $store);
            $this->assertTrue($r->allow, "seq $seq: " . implode('; ', $r->reasons));
            $this->assertSame('pass', $r->checks['beacon'], "seq $seq");
            $this->assertSame([[$key, $seq]], $store->raised, "seq $seq");
        }
    }

    public function testABeaconWithAStoreThatHasNoPinsIsNeverAReplay(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 1);
        $plain = new class () {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }
        };
        $r = $this->bz($this->bound($b), self::cfg($kp, $b), $plain);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['beacon']);
    }

    public function testAStoreThatReadsPinsButCannotRaiseThemStillAdmits(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 2);
        $readOnly = new class () {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }

            public function pin(string $key): ?int
            {
                return null;
            }
        };
        $r = $this->bz($this->bound($b), self::cfg($kp, $b), $readOnly);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['beacon']);
    }

    public function testABeaconPinStoreThatThrowsDenies(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 2);
        $r = $this->bz($this->bound($b), self::cfg($kp, $b), self::recStore([], 'raise-throws'));
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['beacon']);
        $this->assertContains('beacon: the beacon pin store failed (fail closed)', $r->reasons);
    }

    public function testABeaconObjectWithoutASeqIsRejectedByTheVerifierNotByAnError(): void
    {
        $kp = KeyPair::generate();
        $r = $this->bz($this->bound(null), ['beacon' => new Obj(), 'issuers' => [$kp->public], 'instance' => 'inst'], self::recStore());
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['beacon']);
        $this->assertContains('beacon: malformed beacon', $r->reasons);
    }

    public function testABeaconTheVerifierRejectsCarriesTheVerifierReason(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 1);
        $r = $this->bz($this->bound($b), self::cfg($kp, $b, 'other'), self::recStore());
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['beacon']);
        $this->assertContains('beacon: wrong instance', $r->reasons);
    }

    public function testABeaconIsScopedToTheGrant(): void
    {
        $kp = KeyPair::generate();
        $other = $this->beacon($kp, 1, 'another-grant');
        $r = $this->bz($this->bound($other), self::cfg($kp, $other), self::recStore());
        $this->assertFalse($r->allow);
        $this->assertContains('beacon: scope not covered', $r->reasons);
        $own = $this->beacon($kp, 1, $this->gid());
        $r = $this->bz($this->bound($own), self::cfg($kp, $own), self::recStore());
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['beacon']);
    }

    public function testAPcactnThatDoesNotBindTheBeaconIsRefused(): void
    {
        $kp = KeyPair::generate();
        $b = $this->beacon($kp, 1);
        $why = 'beacon: PCActn freshness.beacon_ref does not bind the presented beacon';
        $r = $this->bz($this->bound(null), self::cfg($kp, $b), self::recStore());
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['beacon']);
        $this->assertContains($why, $r->reasons);
        // no freshness member at all
        $r = $this->bz($this->p()->without('freshness'), self::cfg($kp, $b), self::recStore());
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['beacon']);
        $this->assertContains($why, $r->reasons);
    }

    // ---- the durable contract -----------------------------------------------------------------------------------------------

    private static function contractSpy(array $peek, array $check): object
    {
        return new class ($peek, $check) {
            /** @var list<array> */
            public array $calls = [];

            public function __construct(private array $p, private array $c)
            {
            }

            public function peek(Obj $action): array
            {
                $this->calls[] = ['peek', Json::canonicalizeStrict($action)];
                return $this->p;
            }

            public function check(Obj $action, bool $permitted = true): array
            {
                $this->calls[] = ['check', Json::canonicalizeStrict($action), $permitted];
                return $this->c;
            }
        };
    }

    private function contractAction(): string
    {
        return Json::canonicalizeStrict(Obj::of(['action' => Obj::of(['verb' => $this->op->get('verb'),
            'resource' => $this->op->get('resource'), 'params' => $this->op->get('params')])]));
    }

    public function testAContractIsPeekedThenCommittedOnceTheActionIsAdmitted(): void
    {
        $ok = ['allow' => true, 'reason' => 'ok', 'violated' => []];
        $spy = self::contractSpy($ok, $ok);
        $r = $this->az(['hard' => CalmRisk::hard(['contracts' => $spy])]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['contract']);
        $this->assertSame([['peek', $this->contractAction()], ['check', $this->contractAction(), true]], $spy->calls);
    }

    public function testAContractThatRefusesOnPeekNamesItsViolations(): void
    {
        $spy = self::contractSpy(['allow' => false, 'reason' => 'blocked', 'violated' => ['a', 'b']], ['allow' => true, 'reason' => '', 'violated' => []]);
        $r = $this->az(['hard' => CalmRisk::hard(['contracts' => $spy])]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['contract']);
        $this->assertContains('contract: blocked (a,b)', $r->reasons);
        $this->assertSame([['peek', $this->contractAction()]], $spy->calls, 'a refused peek commits nothing');
        $spy = self::contractSpy(['allow' => false, 'reason' => 'blocked', 'violated' => []], ['allow' => true, 'reason' => '', 'violated' => []]);
        $r = $this->az(['hard' => CalmRisk::hard(['contracts' => $spy])]);
        $this->assertContains('contract: blocked', $r->reasons);
    }

    public function testAContractThatRefusesOnCommitDeniesTheAdmittedAction(): void
    {
        $ok = ['allow' => true, 'reason' => 'ok', 'violated' => []];
        $spy = self::contractSpy($ok, ['allow' => false, 'reason' => 'latched', 'violated' => ['x', 'y']]);
        $r = $this->az(['hard' => CalmRisk::hard(['contracts' => $spy])]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['contract']);
        $this->assertContains('contract: latched (x,y)', $r->reasons);
        $spy = self::contractSpy($ok, ['allow' => false, 'reason' => 'latched', 'violated' => []]);
        $r = $this->az(['hard' => CalmRisk::hard(['contracts' => $spy])]);
        $this->assertContains('contract: latched', $r->reasons);
    }

    // ---- the risk hook, the adaptive policy and the threshold hook -----------------------------------------------------------

    private function weighted(float $theta1 = 0.25, float $theta2 = 0.6): Obj
    {
        $g = self::copy($this->grant);
        foreach ($g->get('caveats') as $cv) {
            if ($cv->get('type') === 'envelope') {
                $cv->set('risk_policy', Json::parseLax('{"bMax":1,"kappa":1,"lambda":0.0005,"rho":0.5,"theta1":' . $theta1 . ',"theta2":' . $theta2
                    . ',"weights":{"alpha":0.25,"beta":0.2,"delta":0.2,"epsilon":0.1,"gamma":0.2,"zeta":0.05}}'));
            }
        }
        return $g;
    }

    private function cautious(): Obj
    {
        $p = $this->p();
        $p->set('caution', new Num('0.9'));
        return $p;
    }

    public function testTheRiskHookGetsTheVerbTheResourceAndTheParams(): void
    {
        $seen = [];
        $risk = static function (array $op, Obj $grant, Obj $p) use (&$seen): array {
            $seen[] = [$op, $grant, $p];
            return CalmRisk::inputs();
        };
        $r = $this->az(['hard' => ['risk' => $risk]]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertCount(1, $seen);
        $this->assertSame(['verb', 'resource', 'params'], array_keys($seen[0][0]));
        $this->assertSame($this->op->get('verb'), $seen[0][0]['verb']);
        $this->assertSame($this->op->get('resource'), $seen[0][0]['resource']);
        $this->assertSame(Json::canonicalizeStrict($this->op->get('params')), Json::canonicalizeStrict($seen[0][0]['params']));
        $this->assertSame($this->gid(), $seen[0][1]->get('id'));
        $this->assertSame($this->p->get('grant_ref'), $seen[0][2]->get('grant_ref'));
    }

    public function testARiskHookMayAnswerWithAnObjectOfJsonNumbers(): void
    {
        $answer = Obj::of(['semanticDistance' => new Num('0'), 'reversibility' => new Num('1'), 'blastRadius' => new Num('0.5'),
            'taint' => new Num('0'), 'confidence' => new Num('1'), 'age' => new Num('0')]);
        $r = $this->az(['hard' => ['risk' => static fn() => $answer, 'requireRiskInputs' => ['blastRadius', 'taint']]]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['risk_inputs']);
        // an input the object does not carry is not supplied
        $partial = Obj::of(['taint' => new Num('0')]);
        $r = $this->az(['hard' => ['risk' => static fn() => $partial, 'requireRiskInputs' => ['taint', 'blastRadius']]]);
        $this->assertSame('fail', $r->checks['risk_inputs']);
        $this->assertContains('risk_inputs: required risk input(s) not supplied by the server: blastRadius', $r->reasons);
    }

    public function testRequiredRiskInputsAreSuppliedByTheContextOrTheServerOnly(): void
    {
        $ctx = static fn() => ['risk' => Obj::of(['taint' => new Num('0.2')])];
        // the context supplies taint
        $r = $this->az(['context' => $ctx, 'hard' => ['requireRiskInputs' => ['taint']]]);
        $this->assertSame('pass', $r->checks['risk_inputs']);
        // the server supplies it
        $r = $this->az(['hard' => ['risk' => static fn() => ['taint' => 0.2], 'requireRiskInputs' => ['taint']]]);
        $this->assertSame('pass', $r->checks['risk_inputs']);
        // neither does
        $r = $this->az(['hard' => ['requireRiskInputs' => ['taint']]]);
        $this->assertSame('fail', $r->checks['risk_inputs']);
        $this->assertContains('risk_inputs: required risk input(s) not supplied by the server: taint', $r->reasons);
        // a context value that is not a finite number is no input (1e999 parses to infinity)
        $inf = static fn() => ['risk' => Obj::of(['taint' => new Num('1e999')])];
        $r = $this->az(['context' => $inf, 'hard' => ['requireRiskInputs' => ['taint']]]);
        $this->assertSame('fail', $r->checks['risk_inputs']);
        // a server value that is not a number is no input either
        $r = $this->az(['hard' => ['risk' => static fn() => ['taint' => 'high'], 'requireRiskInputs' => ['taint']]]);
        $this->assertSame('fail', $r->checks['risk_inputs']);
    }

    public function testARiskHookThatThrowsFailsThePolicyClosed(): void
    {
        $risk = static function (): array {
            throw new \RuntimeException('down');
        };
        $r = $this->az(['hard' => ['risk' => $risk]]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['policy']);
        $this->assertContains('policy: policy evaluation error (fail closed)', $r->reasons);
    }

    public function testAnUnreadableLastHopIsNoBudgetHolderAndNoPolicyError(): void
    {
        $p = $this->p();
        $p->set('cap_chain', ['not a hop']);
        $r = $this->az(['pcactn' => $p]);
        $this->assertFalse($r->allow);
        $this->assertContains('delegated_caveats: delegation caveat(s) not satisfied: <malformed caveats>', $r->reasons);
        $this->assertNotContains('policy: policy evaluation error (fail closed)', $r->reasons);
    }

    public function testALateAdaptivePolicyThatNarrowsIsAFailedCheck(): void
    {
        // no risk hook: the early comparison is skipped and the guard's own risk (the missing inputs at their worst) decides
        $adaptive = static fn(int $now): array => ['bMax' => 1, 'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'theta1' => 0.05, 'theta2' => 0.5,
            'weights' => ['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05]];
        $r = $this->az(['grant' => $this->weighted(0.75, 0.9), 'hard' => ['adaptivePolicy' => $adaptive]]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['adaptive']);
        $this->assertContains('adaptive: tightened policy requires threshold t=3 (grant policy: t=1)', $r->reasons);
    }

    public function testAThresholdHookThatDoesNotSayItEnforcesIsNotEnforcing(): void
    {
        $mk = static fn(array $h): array => ['risk' => CalmRisk::source(), 'thresholdHook' => static fn() => $h];
        $r = $this->az(['grant' => $this->weighted(), 'pcactn' => $this->cautious(), 'hard' => $mk(['ok' => true, 't' => 3])]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['threshold']);
        $this->assertContains('threshold: t=3 (strong) required but no threshold verifier is enforced', $r->reasons);
    }

    public function testAThresholdHookThatDoesNotSayOkIsARejection(): void
    {
        $mk = static fn(array $h): array => ['risk' => CalmRisk::source(), 'thresholdHook' => static fn() => $h];
        $r = $this->az(['grant' => $this->weighted(), 'pcactn' => $this->cautious(), 'hard' => $mk(['enforced' => true, 't' => 3])]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['threshold']);
        $this->assertContains('threshold: t=3 required and the threshold proof was rejected', $r->reasons);
    }

    public function testAFailedReleaseNeverReachesTheThresholdCheck(): void
    {
        $hard = ['risk' => CalmRisk::source()];
        $p = $this->cautious();
        // sanity: a releasing action with that caution does reach the threshold check
        $r = $this->az(['grant' => $this->weighted(), 'pcactn' => $p, 'hard' => $hard]);
        $this->assertSame('fail', $r->checks['threshold']);
        // the capability chain failed
        self::core(['chain' => false]);
        $r = $this->az(['grant' => $this->weighted(), 'pcactn' => $p, 'hard' => $hard]);
        $this->assertFalse($r->allow);
        $this->assertArrayNotHasKey('threshold', $r->checks);
        self::core();
        // a delegated caveat failed
        $d = $this->cautious();
        $d->set('cap_chain', ['not a hop']);
        $r = $this->az(['grant' => $this->weighted(), 'pcactn' => $d, 'hard' => $hard]);
        $this->assertSame('fail', $r->checks['delegated_caveats']);
        $this->assertArrayNotHasKey('threshold', $r->checks);
        // the policy failed
        $g = $this->weighted();
        foreach ($g->get('caveats') as $cv) {
            if ($cv->get('type') === 'envelope') {
                $cv->set('predicates', [Json::parseLax('{"verb":"payments.send","resource":"payments/*","where":[{"field":"action.reversibility_class","op":"eq","value":"rate_limited"}]}')]);
            }
        }
        $r = $this->az(['grant' => $g, 'pcactn' => $p, 'hard' => $hard]);
        $this->assertSame('fail', $r->checks['policy']);
        $this->assertArrayNotHasKey('threshold', $r->checks);
    }

    // ---- the replay claim ---------------------------------------------------------------------------------------------------

    private static function conflictStore(): object
    {
        return new class () implements BudgetStateStore {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }

            public function budget(string $key): ?array
            {
                return null;
            }

            public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult
            {
                return new ClaimResult(false, null, true);
            }
        };
    }

    public function testAStoreWithoutBudgetsClaimsThroughClaim(): void
    {
        $plain = new class () {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }
        };
        $r = $this->az(['stateStore' => $plain]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['replay']);
    }

    public function testABudgetConflictIsAnExplicitRetryableRefusal(): void
    {
        $r = $this->az(['stateStore' => self::conflictStore()]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['replay']);
        $this->assertContains('replay: the trust budget changed concurrently (another instance spent first): retry', $r->reasons);
    }

    public function testAContextBudgetIsNeverSettledThroughTheBudgetClaim(): void
    {
        $budget = Obj::of(['B' => new Num('1'), 'tau' => new Num((string)$this->now)]);
        $r = $this->az(['stateStore' => self::conflictStore(), 'context' => static fn() => ['budget' => $budget]]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame('pass', $r->checks['replay']);
    }
}
