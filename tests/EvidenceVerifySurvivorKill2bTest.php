<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\EvidenceVerify;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore;
use PHPUnit\Framework\TestCase;

/**
 * The evidence replay's verifier-context rebuild for a PCActn that carries `intent_session` (the core v2 checks schema,
 * intent_session and accumulators run on state the replay derives from the bundle), the sequencer key-set history and the
 * reservation receipts at their boundaries. Fixtures are the reference's `intent_session/ok` and walkthrough cases
 * (test-data/ref-evidence-bundle-py.json.gz) with artifacts re-signed by the generator's deterministic Ed25519 seeds (byte i of seed n
 * = (31n + 7i + 1) mod 256): 2 the agent, 4 the revocation authority, 6 the sequencer root, 7 the sequencer key k1.
 *
 * The admitted PCActn P is rebuilt at seq 1 under D_1 (same capability chain as the case's own intent_session PCActn) with params
 * total 1000 and claims trip_spend (site-local: the replayed pre-state + 1000) and trip_budget (sequenced: a receipt pre 77800,
 * delta 1000, post 78800). Its envelope.intent does not open D_1's goal commitment (the salt is not in the case), so its v1 `intent`
 * check fails; pcactn.session reads only the v2 checks.
 */
final class EvidenceVerifySurvivorKill2bTest extends TestCase
{
    private const WALK = 'verifyEvidenceBundle/walkthrough#0';
    private const OK = 'verifyEvidenceBundle/intent_session/ok#197';
    private const SESSION = 'SFWPjbv4MgR4wVQHWz7lyLpC9GDFIszx0MSXacPrlKc';
    private const SROOT = 'dZjVh14qZ8gmlSEbkGhJtO499UsAd8PUzxOf0ZoDwX8';
    private const SCHEMA = 'iKG4bC5fWDTv5K-QjgkQiNtBow7WsdMCUNL7ZhuBR5I';
    private const MAP1 = 'p2WUazMHIgVnfyc3cGsOE3y7N--9gay08gsyldznjRk';
    private const Z = 'zX3GA68C_FnIv17YbdKtLQd_R5btQKPCNc1X2e9_I5I';     // seq-1 PCActn at 1793534405000 (params total 77800)
    private const RMN9 = 'Rmn9oGf4jQzYfUWboIv68REtvgkOvbo6OUQV-tI8G2k';  // G_0 PCActn, no effect record (no params)
    private const IAT = 1793534405500;
    private const T_Z = 1793534405000;
    private const SKEW = 60000;
    private const NOT_FRESH = 'not signed by a key the pinned sequencer root listed, or not fresh, at admission time';

    private const TPL = [
        'shape' => 'The bundle is well formed (pca-intent-evidence v1, closed members)',
        'pcactn.verify' => 'The PCActn verifies (signature, chain, audience, validity at its issue time)',
        'pcactn.root' => "The PCActn's root capability is G_0 or a bundled delta grant",
        'pcactn.session' => "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events",
        'accumulator.receipts' => 'The sequencer reservation receipt verifies and is consistent',
        'acc.keysets' => "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back",
    ];

    /** @var array<string,string> */
    private static array $lines = [];

    // ---- shared helpers ------------------------------------------------------------------------------------------------------

    /** @return array{0:Obj,1:Obj} a fresh [bundle, trust]; `trust.verifiers` constants become ports returning them */
    private static function load(string $name): array
    {
        if (!isset(self::$lines[$name])) {
            $h = gzopen(__DIR__ . '/../test-data/ref-evidence-bundle-py.json.gz', 'rb');
            self::assertNotFalse($h);
            while (($l = gzgets($h)) !== false) {
                if (str_contains(substr($l, 0, 200), '"name":"' . $name . '"')) {
                    self::$lines[$name] = rtrim(rtrim($l, "\r\n"), ',');
                    break;
                }
            }
            gzclose($h);
            self::assertArrayHasKey($name, self::$lines, "case $name not found");
        }
        [$b, $t] = (new Parser(self::$lines[$name], PHP_INT_MAX))->run()->get('args');
        $v = $t->get('verifiers');
        if ($v instanceof Obj) {
            $ports = new Obj();
            foreach ($v->keys() as $k) {
                $verdict = $v->get($k);
                $ports->set($k, static fn($artifact, $bundle) => $verdict);
            }
            $t->set('verifiers', $ports);
        }
        return [$b, $t];
    }

    private static function j(string $json): mixed
    {
        return (new Parser($json, 64))->run();
    }

    private static function rt(mixed $v): mixed
    {
        return self::j(Json::canonicalizeNative($v));
    }

    private static function n(int|string $v): Num
    {
        return new Num((string)$v);
    }

    private static function seed(int $n): string
    {
        $s = '';
        for ($i = 0; $i < 32; $i++) {
            $s .= chr(($n * 31 + $i * 7 + 1) & 0xff);
        }
        return $s;
    }

    private static function copy(Obj $o, array $set = [], array $drop = []): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            if (!in_array($k, $drop, true)) {
                $c->set($k, $o->get($k));
            }
        }
        foreach ($set as $k => $v) {
            $c->set((string)$k, $v);
        }
        return $c;
    }

    private static function txt(string $code, string $status, ?string $detail = null): string
    {
        $s = ['pass' => 'verified', 'fail' => 'REFUTED', 'unverified' => 'not verified here'][$status];
        return self::TPL[$code] . ': ' . $s . ($detail !== null ? " ($detail)" : '') . '.';
    }

    /** @return list<array{0:string,1:string,2:array}> */
    private static function fs(Obj $r, string $code): array
    {
        $out = [];
        foreach ($r->get('findings') as $f) {
            if ($f->get('code') === $code) {
                $out[] = [$f->get('status'), $f->get('text'), $f->get('refs')];
            }
        }
        return $out;
    }

    private static function one(Obj $r, string $code, array $refs): string
    {
        $m = array_values(array_filter(self::fs($r, $code), static fn(array $x): bool => $x[2] === $refs));
        self::assertCount(1, $m, "$code " . implode(',', $refs) . ': ' . json_encode(self::fs($r, $code)));
        return $m[0][1];
    }

    private static function completed(Obj $r): void
    {
        self::assertSame([['pass', self::txt('shape', 'pass'), []]], self::fs($r, 'shape'));
    }

    private static function pcactnOf(Obj $b, string $digest): Obj
    {
        foreach ($b->get('pcactns') as $p) {
            if (Pca::hashCanonical($p) === $digest) {
                return $p;
            }
        }
        throw new \RuntimeException("no pcactn $digest");
    }

    private static function ev(string $acc, int $post, string $d, string $status = 'committed'): Obj
    {
        return Obj::of(['acc' => $acc, 'post' => self::n($post), 'pcactn_digest' => $d, 'status' => $status]);
    }

    /** A sequencer key set signed by the session's sequencer root (seed 6). */
    private static function keySet(int $version, int $issuedAt, array $keys): Obj
    {
        return self::rt(SignersMore::signSequencerKeySet(Obj::of(['v' => self::n(1), 'kind' => 'pca-sequencer-keys', 'version' => self::n($version),
            'issued_at' => self::n($issuedAt), 'keys' => $keys]), new KeyPair(self::seed(6))));
    }

    /** The case's key k1 entry (seed 7, not_before 1793533800000), optionally under another kid (then no receipt names it). */
    private static function key(Obj $b, string $kid = 'k1'): Obj
    {
        return self::copy($b->get('accumulator')->get('sequencer_keys')[0]->get('keys')[0], ['kid' => $kid]);
    }

    // ---- the admitted intent_session PCActn ----------------------------------------------------------------------------------

    /**
     * The `intent_session/ok` case with P (see the class comment), its effect record, its reservation receipt R and a PCActn Q that
     * carries intent_session but is rooted at no verified grant. Options: iat, age (R issued_at = iat - age), expires (R expires_at),
     * spend (P's trip_spend claim), layout (the accumulator events: committed | released | first | none).
     * @return array{0:Obj,1:Obj,2:Obj,3:string,4:Obj}
     */
    private static function admitted(array $o = []): array
    {
        [$b, $t] = self::load(self::OK);
        $iat = $o['iat'] ?? self::IAT;
        $own = null;
        foreach ($b->get('pcactns') as $p) {
            if ($p->has('intent_session')) {
                $own = $p;
            }
        }
        self::assertNotNull($own);
        $d1 = $b->get('deltas')[0];
        $zEffect = $b->get('effects')[0];
        self::assertSame(self::Z, $zEffect->get('pcactn_digest'));
        $params = self::copy($zEffect->get('params'), ['total' => self::n(1000)]);
        $r0 = $b->get('accumulator')->get('receipts')[0];
        $intent = Obj::of(['ref' => $b->get('session_root')->get('intent_ref'), 'map_digest' => self::MAP1, 'goal_salt' => 's',
            'fidelity_ppm' => self::n(900000), 'residual_risk_ppm' => self::n(1000)]);
        $mk = static fn(array $acc): Obj => self::rt(Sign::buildPcactn($d1, $own->get('cap_chain'),
            [['id' => 'n1', 'verb' => 'air.book', 'resource' => 'skyair.example/bookings', 'reversibility_class' => 'irreversible']], 'n1', 4,
            new KeyPair(self::seed(2)), 'skyair.example', $params, iat: $iat, exp: 1793535000000,
            extra: ['intent' => $intent, 'intent_session' => Obj::of(['session' => self::SESSION, 'root' => self::SROOT, 'seq' => self::n(1),
                'schema' => self::SCHEMA, 'acc' => $acc])]));
        $resv = IntentV2::pcactnReservationDigest($mk([])); // intent_session is outside the reservation digest
        $receipt = self::rt(SignersMore::signAccReceipt(Obj::of(['v' => self::n(1), 'kind' => 'pca-acc-receipt', 'session' => self::SESSION,
            'acc' => 'trip_budget', 'seq' => self::n(2), 'pre' => self::n(77800), 'delta' => self::n(1000), 'post' => self::n(78800),
            'pcactn_digest' => $resv, 'aud' => 'skyair.example', 'issued_at' => self::n($iat - ($o['age'] ?? 200)),
            'expires_at' => self::n($o['expires'] ?? $iat), 'kid' => 'k1',
            'ledger' => Obj::of(['index' => self::n(1), 'head' => $r0->get('ledger')->get('head')])]), new KeyPair(self::seed(7))));
        $layout = $o['layout'] ?? 'committed';
        $spend = $o['spend'] ?? ($layout === 'committed' ? 78800 : 1000);
        $p = $mk([Obj::of(['id' => 'trip_spend', 'post' => self::n($spend)]),
            Obj::of(['id' => 'trip_budget', 'post' => self::n(78800), 'receipt' => IntentV2::accReceiptDigest($receipt)])]);
        self::assertSame($resv, IntentV2::pcactnReservationDigest($p));
        $d = Pca::hashCanonical($p);
        $q = self::copy($p, ['cap_chain' => [Obj::of(['id' => 'nope'])]]);
        $b->set('pcactns', [...$b->get('pcactns'), $p, $q]);
        $b->set('effects', [$zEffect, Obj::of(['pcactn_digest' => $d, 'params' => $params])]);
        $b->get('accumulator')->set('receipts', [$r0, $receipt]);
        $z = [self::ev('trip_spend', 77800, self::Z), self::ev('trip_budget', 77800, self::Z)];
        $mine = [self::ev('trip_spend', $spend, $d), self::ev('trip_budget', 78800, $d)];
        $events = match ($layout) {
            'committed' => [self::ev('trip_budget', 0, self::RMN9), ...$z, ...$mine],
            'released' => [self::ev('trip_budget', 0, self::RMN9), self::ev('trip_spend', 0, self::Z, 'released'), $z[1], ...$mine],
            'first' => [...$mine, ...$z],
            'none' => $z,
        };
        $b->get('accumulator')->set('events', $events);
        return [$b, $t, $p, $d, $receipt];
    }

    private static function session(Obj $r, string $d): string
    {
        return self::one($r, 'pcactn.session', ["pcactn:$d"]);
    }

    private static function v2Failed(string $names): string
    {
        return self::txt('pcactn.session', 'fail', "core v2 checks failed: $names");
    }

    /**
     * The rebuilt verifier state admits P: the session grants in seq order, the epoch in force, the receipts and the key sets in
     * force, and the site-local pre-state replayed from the history before P (the first event of each PCActn, Z's committed 77800;
     * the leading event of a PCActn without params is skipped, not the end of the history). Its receipt verifies at the boundary
     * admission time == expires_at.
     */
    public function testTheRebuiltVerifierStateAdmitsTheSessionPcactn(): void
    {
        [$b, $t, , $d, $receipt] = self::admitted();
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
        $this->assertSame(self::txt('pcactn.root', 'pass', 'D_1'), self::one($r, 'pcactn.root', ["pcactn:$d"]));
        $this->assertSame(self::txt('accumulator.receipts', 'pass'), self::one($r, 'accumulator.receipts', ['receipt:trip_budget#2']));
        $this->assertSame(self::IAT, $receipt->get('expires_at')->int());
    }

    /** A released event keeps a PCActn's history entry uncounted (the status is the event's, not a default). */
    public function testAReleasedFirstEventLeavesThePreStateEmpty(): void
    {
        [$b, $t, , $d] = self::admitted(['layout' => 'released']);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
    }

    /** P's own first event opens the history: the pre-state is the (empty) prefix before it, never the time filter. */
    public function testTheFirstHistoryEntryHasAnEmptyPrefix(): void
    {
        [$b, $t, , $d] = self::admitted(['layout' => 'first']);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.session', 'pass'), self::session($r, $d));
    }

    /** A wrong claim is refused by the replayed pre-state (control: the state is really read). */
    public function testAClaimThatIgnoresTheHistoryIsRefused(): void
    {
        [$b, $t, , $d] = self::admitted(['spend' => 1000]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::v2Failed('accumulators'), self::session($r, $d));
    }

    /** trust.acc.max_receipt_age_s bounds the receipt age to the ms (age 1001 > 1000) in the replay and in the v2 policy. */
    public function testTheReceiptAgeBoundIsExactMilliseconds(): void
    {
        [$b, $t, , $d] = self::admitted(['age' => 1001]);
        $t->set('acc', self::j('{"max_receipt_age_s": 1}'));
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('accumulator.receipts', 'fail', self::NOT_FRESH), self::one($r, 'accumulator.receipts', ['receipt:trip_budget#2']));
        $this->assertSame(self::txt('accumulator.receipts', 'pass'), self::one($r, 'accumulator.receipts', ['receipt:trip_budget#1']));
        $this->assertSame(self::v2Failed('accumulators'), self::session($r, $d));
    }

    /** trust.acc.max_keyset_age_s bounds the key-set age to the ms (5001 > 5000) in the replay and in the v2 policy. */
    public function testTheKeySetAgeBoundIsExactMilliseconds(): void
    {
        [$b, $t, , $d] = self::admitted(['iat' => 1793534405001]);
        $t->set('acc', self::j('{"max_keyset_age_s": 5}'));
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('accumulator.receipts', 'fail', self::NOT_FRESH), self::one($r, 'accumulator.receipts', ['receipt:trip_budget#2']));
        $this->assertSame(self::txt('accumulator.receipts', 'pass'), self::one($r, 'accumulator.receipts', ['receipt:trip_budget#1']));
        $this->assertSame(self::v2Failed('accumulators'), self::session($r, $d));
    }

    /** A receipt that expired 1 ms before admission is refused as expired (not passed with a reason). */
    public function testAReceiptExpiredAtAdmissionIsRefused(): void
    {
        [$b, $t, , $d] = self::admitted(['expires' => self::IAT - 1]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('accumulator.receipts', 'fail', 'the receipt had expired when the action was admitted'),
            self::one($r, 'accumulator.receipts', ['receipt:trip_budget#2']));
        $this->assertSame(self::v2Failed('accumulators'), self::session($r, $d));
    }

    /** The epoch before the one in force is the tracked `last`: a later epoch with a lower number is a rollback. */
    public function testTheEpochBeforeTheOneInForceIsTheTrackedLast(): void
    {
        [$b, $t, , $d] = self::admitted();
        $ep0 = $b->get('revocation_epochs')[0];
        $e = self::copy($ep0->get('epoch'), ['epoch' => self::n(2), 'issued_at' => self::n(1793534404000), 'not_after' => self::n(1793534704000)]);
        $body = new Obj();
        foreach (['instance_id', 'grant_ref', 'epoch', 'set_size', 'root', 'issued_at', 'not_after'] as $k) {
            $body->set($k, $e->get($k));
        }
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed(4)));
        $e->set('sig', Pca::b64u(sodium_crypto_sign_detached(IntentV2::REVEPOCH_DOMAIN . IntentV2::canonicalize($body), $sk)));
        $b->set('revocation_epochs', [Obj::of(['epoch' => $e, 'revoked' => $ep0->get('revoked')]), $ep0]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::v2Failed('intent_session'), self::session($r, $d));
    }

    /**
     * Two different key sets at the newest version poison it: only sets at or above it that are not equivocating are in force, so
     * the older set listing k1 does not admit the receipt; a later non-equivocating set listing k1 does (no tracked version is
     * passed for the poisoned root).
     */
    public function testAnEquivocatedNewestVersionKeepsOlderSetsOutOfForce(): void
    {
        foreach ([false, true] as $later) {
            [$b, $t, , $d] = self::admitted();
            $k1 = self::key($b);
            $sets = [$b->get('accumulator')->get('sequencer_keys')[0], self::keySet(2, 1793534401000, [self::key($b, 'k2')]),
                self::keySet(2, 1793534402000, [self::key($b, 'k3')])];
            if ($later) {
                $sets[] = self::keySet(3, self::IAT + 10000, [$k1]);
            }
            $b->get('accumulator')->set('sequencer_keys', $sets);
            $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
            self::completed($r);
            $this->assertSame($later ? self::txt('pcactn.session', 'pass') : self::v2Failed('accumulators'), self::session($r, $d));
        }
    }

    /** Two PCActns with one reservation digest: the receipt is judged against the FIRST in bundle order. */
    public function testAReceiptIsJudgedAgainstTheFirstPcactnWithItsReservationDigest(): void
    {
        [$b, $t, $p, $d, $receipt] = self::admitted();
        $is = $p->get('intent_session');
        $twinIs = self::copy($is, ['acc' => [Obj::of(['id' => 'trip_spend', 'post' => self::n(1)]), $is->get('acc')[1]]]);
        $twin = self::rt(Sign::signPcactn(self::copy($p, ['intent_session' => $twinIs], ['sig']), new KeyPair(self::seed(2))));
        $dt = Pca::hashCanonical($twin);
        $this->assertSame(IntentV2::pcactnReservationDigest($p), IntentV2::pcactnReservationDigest($twin));
        $first = strcmp($d, $dt) < 0 ? $d : $dt; // equal iat and counter: the normal form orders by digest
        $b->set('pcactns', [...$b->get('pcactns'), $twin]);
        $b->set('effects', [$b->get('effects')[0], Obj::of(['pcactn_digest' => $first, 'params' => $b->get('effects')[1]->get('params')])]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('accumulator.receipts', 'pass'), self::one($r, 'accumulator.receipts', ['receipt:trip_budget#2']));
        $this->assertSame(78800, $receipt->get('post')->int());
    }

    // ---- the time filter for a PCActn without an event of its own -------------------------------------------------------------

    /** A copy of Z at `$iat` whose effect params cannot be accumulated, with one counted event. @return array{0:Obj,1:string} */
    private static function junk(Obj $b, int $iat): array
    {
        $j = self::copy(self::pcactnOf($b, self::Z), ['iat' => self::n($iat)]);
        $dj = Pca::hashCanonical($j);
        $b->set('pcactns', [...$b->get('pcactns'), $j]);
        $b->set('effects', [...$b->get('effects'), Obj::of(['pcactn_digest' => $dj, 'params' => Obj::of(['total' => 'x'])])]);
        $b->get('accumulator')->set('events', [...$b->get('accumulator')->get('events'), self::ev('trip_spend', 0, $dj)]);
        return [$j, $dj];
    }

    /** Without an event of its own, P's pre-state replays every history entry stamped at or before its iat (here one that throws). */
    public function testWithoutItsOwnEventTheHistoryUpToTheIatIsReplayed(): void
    {
        [$b, $t] = self::admitted(['layout' => 'none']);
        [, $dj] = self::junk($b, self::IAT);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        $this->assertContains(['fail', self::TPL['shape'] . ': REFUTED (replay aborted: event ' . $dj . ': action.params.total must be a non-negative safe integer).', []],
            self::fs($r, 'shape'));
    }

    /** ... and no entry stamped after it (by the entry's own PCActn iat). */
    public function testWithoutItsOwnEventLaterHistoryIsNotReplayed(): void
    {
        [$b, $t, , $d] = self::admitted(['layout' => 'none']);
        self::junk($b, self::IAT + 1);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertStringContainsString('has no matching accumulator event', self::session($r, $d));
    }

    // ---- sequencer key sets on the walkthrough's receipt (admitted at Z's iat) ------------------------------------------------

    /** @param list<Obj> $sets */
    private static function walkthroughWith(callable $sets): Obj
    {
        [$b, $t] = self::load(self::WALK);
        $b->get('accumulator')->set('sequencer_keys', $sets($b));
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        return $r;
    }

    private static function walkReceipt(Obj $r): string
    {
        return self::one($r, 'accumulator.receipts', ['receipt:trip_budget#1']);
    }

    /** A set issued exactly at admission is the newest in force (here without k1, so the receipt is refused). */
    public function testASetIssuedAtAdmissionIsInForce(): void
    {
        $r = self::walkthroughWith(static fn(Obj $b): array => [$b->get('accumulator')->get('sequencer_keys')[0], self::keySet(2, self::T_Z, [self::key($b, 'k2')])]);
        $this->assertSame(self::txt('accumulator.receipts', 'fail', self::NOT_FRESH), self::walkReceipt($r));
        $this->assertSame(self::txt('acc.keysets', 'pass'), self::one($r, 'acc.keysets', ['keyset#1:2']));
    }

    /** A set issued after admission does not raise the version floor (the older set listing k1 stays in force). */
    public function testALaterSetDoesNotRaiseTheFloor(): void
    {
        $r = self::walkthroughWith(static fn(Obj $b): array => [$b->get('accumulator')->get('sequencer_keys')[0], self::keySet(3, self::T_Z + 10000, [self::key($b, 'k2')])]);
        $this->assertSame(self::txt('accumulator.receipts', 'pass'), self::walkReceipt($r));
    }

    /** The receipt-skew window is inclusive: a set issued exactly 60 s after admission still admits the receipt. */
    public function testASetIssuedAtTheSkewBoundIsInForce(): void
    {
        $r = self::walkthroughWith(static fn(Obj $b): array => [self::keySet(1, self::T_Z + self::SKEW, [self::key($b)])]);
        $this->assertSame(self::txt('accumulator.receipts', 'pass'), self::walkReceipt($r));
        $this->assertSame(self::txt('acc.keysets', 'pass'), self::one($r, 'acc.keysets', ['keyset#0:1']));
    }

    /** An equivocating set and a rollback are refused, and every later set is still judged. */
    public function testRefusedSetsDoNotEndTheKeySetReplay(): void
    {
        $r = self::walkthroughWith(static fn(Obj $b): array => [self::keySet(2, 10, [self::key($b)]), self::keySet(2, 20, [self::key($b, 'k2')]),
            self::keySet(1, 30, [self::key($b)]), self::keySet(3, 40, [self::key($b)])]);
        $this->assertSame(self::txt('acc.keysets', 'pass'), self::one($r, 'acc.keysets', ['keyset#0:2']));
        $eq = self::fs($r, 'acc.keysets.equivocation');
        $this->assertCount(1, $eq);
        $this->assertSame(['fail', ['keyset#0:2', 'keyset#1:2']], [$eq[0][0], $eq[0][2]]);
        $this->assertSame(self::txt('acc.keysets', 'fail', 'version 1 rolls back the tracked version 2'), self::one($r, 'acc.keysets', ['keyset#2:1']));
        $this->assertSame(self::txt('acc.keysets', 'pass'), self::one($r, 'acc.keysets', ['keyset#3:3']));
    }

    // ---- malformed PCActns in the PCActn loop ---------------------------------------------------------------------------------

    /**
     * Junk PCActns (an empty chain, a chain that is not an array, a chain whose root is not an object) are refused one by one and
     * do not end the loop (the subject, issued later, is still found); a PCActn that is not an object is an empty chain.
     */
    public function testMalformedPcactnsAreRefusedOneByOne(): void
    {
        [$b, $t] = self::load(self::WALK);
        $junk = [self::j('{"iat": 0, "cap_chain": []}'), self::j('{"iat": 0, "cap_chain": "x"}'), self::j('{"iat": 0, "cap_chain": ["x"]}')];
        $b->set('pcactns', [...$b->get('pcactns'), ...$junk]);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame('pass', self::fs($r, 'subject.present')[0][0]);
        $empty = self::txt('pcactn.verify', 'fail', 'empty capability chain');
        $this->assertSame($empty, self::one($r, 'pcactn.verify', ['pcactn:' . Pca::hashCanonical($junk[0])]));
        $this->assertSame($empty, self::one($r, 'pcactn.verify', ['pcactn:' . Pca::hashCanonical($junk[1])]));
        $this->assertSame(self::txt('pcactn.root', 'fail', 'rooted at a grant that is not G_0 or a verified delta of this session'),
            self::one($r, 'pcactn.root', ['pcactn:' . Pca::hashCanonical($junk[2])]));
    }

    public function testANonObjectPcactnIsAnEmptyChain(): void
    {
        [$b, $t] = self::load(self::WALK);
        $b->set('pcactns', [...$b->get('pcactns'), 'x']);
        $r = EvidenceVerify::verifyEvidenceBundle($b, $t);
        self::completed($r);
        $this->assertSame(self::txt('pcactn.verify', 'fail', 'empty capability chain'), self::one($r, 'pcactn.verify', ['pcactn:' . Pca::hashCanonical('x')]));
    }
}
